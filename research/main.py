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
    allow_origins=["chrome-extension://mfnbcmbcmegajcidmgodikdonidhfggo"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

# Models
rf_model = None
xgb_model = None
FEATURE_NAMES = None

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
RF_PATH = MODEL_DIR / "phishing_random_forest.joblib"
XGB_PATH = MODEL_DIR / "phishing_xgboost.joblib"

def load_models():
    global rf_model, xgb_model, FEATURE_NAMES
    try:
        if RF_PATH.exists():
            rf_model = joblib.load(RF_PATH)
            logger.info("RF Model Loaded")
        if XGB_PATH.exists():
            xgb_model = joblib.load(XGB_PATH)
            logger.info("XGB Model Loaded")

        rf_f = getattr(rf_model, "feature_names_in_", None)
        xgb_f = getattr(xgb_model, "feature_names_in_", None)

        FEATURE_NAMES = rf_f or xgb_f or [f"f{i}" for i in range(30)]

    except Exception as e:
        logger.error(f"Model Load Error: {e}")

load_models()

VT_KEY = os.getenv("VT_API_KEY")
BACKEND_TOKEN = os.getenv("BACKEND_TOKEN")
VT_CACHE = {}

# ✅ UPDATED REQUEST MODEL
class URLRequest(BaseModel):
    url: str
    signal: str = None  # NEW (domain_mismatch, hidden_form, iframe)
    has_login_form: bool = False
    external_form_action: bool = False
    external_scripts: int = 0


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

    except Exception:
        return 0

    return 0


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"error": "Rate limit exceeded"}
    )


@app.post("/predict")
@limiter.limit("20/minute")
async def predict(request: Request, body: URLRequest):

    #  AUTH
    token = request.headers.get("x-api-key")
    if token != BACKEND_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")

    if rf_model is None or xgb_model is None:
        raise HTTPException(status_code=503, detail="Models not loaded")

    url = body.url.lower().strip()

    # --- DATA ---
    impersonated = detect_clone(url)
    is_trusted = is_globally_trusted(url)
    live = get_domain_info(url)
    vt_hits = check_virustotal(url)

    feat = extract_features(url)
    df = pd.DataFrame([feat], columns=FEATURE_NAMES)

    rf_prob = rf_model.predict_proba(df)[0][1]
    xgb_prob = xgb_model.predict_proba(df)[0][1]
    ai_prob = (rf_prob + xgb_prob) / 2.0

    # --- RISK ENGINE ---
    risk_score = 0
    reasons = []

    #  VirusTotal
    if vt_hits >= 5:
        risk_score += 70
        reasons.append(f"Flagged by {vt_hits} engines")
    elif vt_hits >= 1:
        risk_score += 40
        reasons.append("Suspicious reputation")

    # Clone
    if impersonated:
        risk_score += 60
        reasons.append(f"Impersonating {impersonated}")

    #  Domain age
    if live.get("age_days", 0) < 7:
        risk_score += 40
        reasons.append("Very new domain")

    # SSL
    if not live.get("is_ssl"):
        risk_score += 20
        reasons.append("No SSL")

    #  AI
    if ai_prob > 0.8:
        risk_score += 40
        reasons.append("High phishing pattern")
    elif ai_prob > 0.5:
        risk_score += 20
        reasons.append("Suspicious pattern")

    #  Behavior
    if body.has_login_form:
        risk_score += 25
        reasons.append("Login form detected")

    if body.external_form_action:
        risk_score += 60
        reasons.append("External form submission")

    if body.external_scripts > 2:
        risk_score += 20
        reasons.append("Multiple external scripts")

    #  Advanced signals
    if body.signal == "domain_mismatch":
        risk_score += 90
        reasons.append("Form submits to different domain")

    if body.signal == "hidden_form":
        risk_score += 40
        reasons.append("Hidden login form")

    if body.signal == "iframe":
        risk_score += 30
        reasons.append("Suspicious iframe")

    #  Trusted reduction (NOT override)
    if is_trusted:
        risk_score -= 20
        reasons.append("Trusted domain")

    # Clamp
    risk_score = max(0, min(100, risk_score))

    # --- FINAL ---
    if risk_score >= 80:
        verdict = "Dangerous website"
        risk_level = "High"
        is_phishing = True
    elif risk_score >= 40:
        verdict = "Suspicious website"
        risk_level = "Medium"
        is_phishing = False
    else:
        verdict = "Safe website"
        risk_level = "Low"
        is_phishing = False

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "is_phishing": is_phishing,
        "reasons": reasons[:3],  # keep clean
        "signals": {
            "ai_probability": round(ai_prob, 2),
            "virus_total_hits": vt_hits,
            "domain_age_days": live.get("age_days"),
            "ssl_active": live.get("is_ssl"),
            "impersonating": impersonated
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)