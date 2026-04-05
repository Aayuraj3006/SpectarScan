import os
import base64
import logging
import time
import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

try:
    from .utils import is_globally_trusted, detect_clone
    from .scanner import get_domain_info
except ImportError:
    from utils import is_globally_trusted, detect_clone
    from scanner import get_domain_info

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SpecterScan Supreme Backend")

# ===== RATE LIMIT =====
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})

# ===== CORS =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["*"],
)

VT_KEY = os.getenv("VT_API_KEY")
GSB_KEY = os.getenv("GSB_API_KEY")
BACKEND_TOKEN = os.getenv("BACKEND_TOKEN")

# ===== CACHE =====
CACHE = {}
TTL_MALICIOUS = 3600
TTL_SAFE = 86400
TTL_DEFAULT = 300

def get_cache(key):
    if key in CACHE:
        data, ts, ttl = CACHE[key]
        if time.time() - ts < ttl:
            return data
        del CACHE[key]
    return None

def set_cache(key, value, ttl=TTL_DEFAULT):
    CACHE[key] = (value, time.time(), ttl)

# ===== MODEL =====
class URLRequest(BaseModel):
    url: str
    has_login_form: bool = False
    external_form_action: bool = False
    external_scripts: int = 0

# ===== VIRUSTOTAL =====
def check_virustotal(url: str):
    url = url.strip().rstrip('/')
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    cached = get_cache(f"vt:{url}")
    if cached is not None:
        return cached

    if not VT_KEY:
        return None

    headers = {"x-apikey": VT_KEY}

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        # No data yet → NOT suspicious
        if resp.status_code == 404:
            requests.post(
                "https://www.virustotal.com/api/v3/urls",
                data={"url": url},
                headers=headers,
                timeout=10
            )
            return None

        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            hits = stats.get("malicious", 0)

            total = sum(stats.values())
            if total > 10:
                set_cache(f"vt:{url}", hits,
                          TTL_MALICIOUS if hits >= 5 else TTL_SAFE)

            return hits

    except Exception as e:
        logger.error(f"VT error: {e}")

    return None

# ===== GOOGLE SAFE BROWSING =====
def check_gsb(url: str):
    cached = get_cache(f"gsb:{url}")
    if cached is not None:
        return cached

    if not GSB_KEY:
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}"

    payload = {
        "client": {"clientId": "specterscan", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=10)
        flagged = resp.status_code == 200 and "matches" in resp.json()

        set_cache(f"gsb:{url}", flagged,
                  TTL_MALICIOUS if flagged else TTL_SAFE)

        return flagged

    except Exception as e:
        logger.error(f"GSB error: {e}")

    return False

# ===== MAIN API =====
@app.post("/predict")
@limiter.limit("20/minute")
async def predict(request: Request, body: URLRequest):

    token = request.headers.get("x-api-key")
    if token != BACKEND_TOKEN:
        raise HTTPException(status_code=403, detail="Forbidden")

    url = body.url.lower().strip()

    cached = get_cache(f"full:{url}")
    if cached:
        return cached

    # ===== SIGNALS =====
    vt_hits = check_virustotal(url)
    gsb_flag = check_gsb(url)
    live = get_domain_info(url)

    is_trusted = is_globally_trusted(url)
    impersonated = detect_clone(url)

    # ===== SCORING =====
    risk = 0
    reasons = []

    # --- Google Safe Browsing (strongest)
    if gsb_flag:
        risk += 90
        reasons.append("Blacklisted by Google Safe Browsing")

    # --- VirusTotal (normalized)
    if vt_hits is not None:
        if vt_hits >= 8:
            risk += 60
            reasons.append(f"Multiple security engines flagged ({vt_hits})")
        elif vt_hits >= 3:
            risk += 30
            reasons.append("Some engines reported suspicious activity")

    # --- Domain age (reduced impact)
    age = live.get("age_days", 0)
    if age == 0:
        risk += 25
        reasons.append("Very new domain")
    elif age < 7:
        risk += 15
        reasons.append("Recently registered domain")

    # --- SSL
    if not live.get("is_ssl"):
        risk += 20
        reasons.append("No SSL certificate")

    # --- IP hosting
    if live.get("is_ip_hosting"):
        risk += 25
        reasons.append("Hosted on raw IP")

    # --- Phishing signals
    if body.external_form_action:
        risk += 40
        reasons.append("Form submits to external domain")

    if impersonated:
        risk += 60
        reasons.append(f"Impersonating {impersonated}")

    # --- TRUST OVERRIDE (important)
    if is_trusted:
        risk = min(risk, 20)

    # Clamp
    risk = max(0, min(100, risk))

    # ===== VERDICT =====
    if gsb_flag:
        verdict = "Dangerous"
    elif risk >= 65:
        verdict = "Dangerous"
    elif risk >= 30:
        verdict = "Suspicious"
    elif vt_hits is None:
        verdict = "Unknown"
    else:
        verdict = "Safe"

    result = {
        "url": url,
        "verdict": verdict,
        "risk_score": risk,
        "reasons": reasons[:3],
        "signals": {
            "vt_hits": vt_hits,
            "gsb_flag": gsb_flag,
            "domain_age": age,
            "ssl": live.get("is_ssl")
        }
    }

    # Cache properly
    set_cache(
        f"full:{url}",
        result,
        TTL_SAFE if verdict in ["Safe", "Unknown"] else TTL_MALICIOUS
    )

    return result

# ===== RUN =====
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))