import os
import base64
import logging
import requests
import joblib
import pandas as pd
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Local imports
try:
    from .utils import extract_features, is_globally_trusted, detect_clone
    from .scanner import get_domain_info
except ImportError:
    from utils import extract_features, is_globally_trusted, detect_clone
    from scanner import get_domain_info

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SpecterScan Supreme")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

# ===== MODEL LOADING =====
rf_model = None
xgb_model = None
FEATURE_NAMES = None

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"

def load_models():
    global rf_model, xgb_model, FEATURE_NAMES

    try:
        rf_path = MODEL_DIR / "phishing_random_forest.joblib"
        xgb_path = MODEL_DIR / "phishing_xgboost.joblib"

        print("RF exists:", rf_path.exists())
        print("XGB exists:", xgb_path.exists())

        if not rf_path.exists() or not xgb_path.exists():
            logger.error("Model files not found")
            return

        rf_model = joblib.load(rf_path)
        xgb_model = joblib.load(xgb_path)

        # FIXED FEATURE NAMES
        FEATURE_NAMES = getattr(rf_model, "feature_names_in_", None)

        if FEATURE_NAMES is None:
            FEATURE_NAMES = getattr(xgb_model, "feature_names_in_", None)

        if FEATURE_NAMES is None:
            FEATURE_NAMES = [f"f{i}" for i in range(30)]
        else:
            FEATURE_NAMES = list(FEATURE_NAMES)

        logger.info(f"Models loaded. Features: {len(FEATURE_NAMES)}")

    except Exception as e:
        logger.error(f"Model load failed: {e}")

load_models()

VT_KEY = os.getenv("VT_API_KEY")
BACKEND_TOKEN = os.getenv("BACKEND_TOKEN")
VT_CACHE = {}

# ===== REQUEST MODEL =====
class URLRequest(BaseModel):
    url: str
    signal: str | None = None
    has_login_form: bool = False
    external_form_action: bool = False
    external_scripts: int = 0

# ===== VIRUSTOTAL =====
def check_virustotal(url: str) -> int:
    if url in VT_CACHE:
        return VT_CACHE[url]

    if not VT_KEY:
        return 0

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_KEY}

        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=3
        )

        if resp.status_code == 200:
            result = resp.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
            VT_CACHE[url] = result
            return result

    except Exception as e:
        logger.error(f"VirusTotal error: {e}")

    return 0

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})

# ===== MAIN ENDPOINT =====
@app.post("/predict")
@limiter.limit("20/minute")
async def predict(request: Request, body: URLRequest):

    try:
        # AUTH
        token = request.headers.get("x-api-key")
        if not BACKEND_TOKEN:
            raise HTTPException(status_code=500, detail="Server config error")
        if token != BACKEND_TOKEN:
            raise HTTPException(status_code=403, detail="Forbidden")

        # MODEL CHECK
        if rf_model is None or xgb_model is None:
            raise HTTPException(status_code=503, detail="Models not loaded")

        url = body.url.lower().strip()
        signal = body.signal

        # FEATURES
        impersonated = detect_clone(url)
        is_trusted = is_globally_trusted(url)

        try:
            live = get_domain_info(url)
        except Exception:
            live = {"age_days": 0, "is_ssl": False}

        vt_hits = check_virustotal(url)

        # EXTRACT FEATURES
        df = pd.DataFrame([extract_features(url)])

        # ✅ CRITICAL FIX: FORCE ALIGNMENT
        df = df.reindex(columns=FEATURE_NAMES, fill_value=0)

        # DEBUG (optional, remove later)
        print("Expected:", len(FEATURE_NAMES))
        print("Actual:", len(df.columns))

        # PREDICTION
        try:
            rf_prob = rf_model.predict_proba(df)[0][1]
            xgb_prob = xgb_model.predict_proba(df)[0][1]
        except Exception as e:
            logger.error(f"Prediction failed: {e}")
            raise HTTPException(status_code=500, detail="Prediction error")

        ai_prob = (rf_prob + xgb_prob) / 2

        # RISK ENGINE
        risk_score = 0
        reasons = []

        if vt_hits >= 5:
            risk_score += 70
            reasons.append(f"{vt_hits} engines flagged")
        elif vt_hits >= 1:
            risk_score += 40
            reasons.append("Suspicious reputation")

        if impersonated:
            risk_score += 60
            reasons.append(f"Impersonating {impersonated}")

        if live.get("age_days", 0) < 7:
            risk_score += 40
            reasons.append("Very new domain")

        if not live.get("is_ssl"):
            risk_score += 20
            reasons.append("No SSL")

        risk_score += ai_prob * 40

        if body.has_login_form:
            risk_score += 25
            reasons.append("Login form detected")

        if body.external_form_action:
            risk_score += 60
            reasons.append("External form action")

        if body.external_scripts > 2:
            risk_score += 20
            reasons.append("Multiple external scripts")

        if signal == "domain_mismatch":
            risk_score += 90
        elif signal == "hidden_form":
            risk_score += 40
        elif signal == "iframe":
            risk_score += 30
        elif signal == "credential_submit":
            risk_score += 100

        if is_trusted:
            risk_score -= 20

        risk_score = max(0, min(100, risk_score))

        if risk_score >= 80:
            verdict = "Dangerous Website"
            risk_level = "High"
            is_phishing = True
        elif risk_score >= 40:
            verdict = "Suspicious Website"
            risk_level = "Medium"
            is_phishing = False
        else:
            verdict = "Safe Website"
            risk_level = "Low"
            is_phishing = False

        return {
            "url": url,
            "verdict": verdict,
            "risk_score": round(risk_score, 2),
            "risk_level": risk_level,
            "is_phishing": is_phishing,
            "reasons": reasons[:3],
            "signals": {
                "ai_probability": round(ai_prob, 2),
                "virus_total_hits": vt_hits,
                "domain_age_days": live.get("age_days"),
                "ssl_active": live.get("is_ssl"),
                "impersonating": impersonated
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Prediction failed: {e}")
        raise HTTPException(status_code=500, detail="Internal processing error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)