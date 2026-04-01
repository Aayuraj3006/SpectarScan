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

# Local imports
try:
    from .utils import is_globally_trusted, detect_clone
    from .scanner import get_domain_info
except ImportError:
    from utils import is_globally_trusted, detect_clone
    from scanner import get_domain_info

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SpecterScan Ultimate")

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
CACHE_TTL = 300  # 5 minutes

def get_cache(key):
    if key in CACHE:
        data, timestamp = CACHE[key]
        if time.time() - timestamp < CACHE_TTL:
            return data
        del CACHE[key]
    return None

def set_cache(key, value):
    CACHE[key] = (value, time.time())

# ===== REQUEST MODEL =====
class URLRequest(BaseModel):
    url: str
    signal: str | None = None
    has_login_form: bool = False
    external_form_action: bool = False
    external_scripts: int = 0

# ===== VIRUSTOTAL =====
def check_virustotal(url: str) -> int:
    cached = get_cache(f"vt:{url}")
    if cached is not None:
        return cached

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
            result = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            set_cache(f"vt:{url}", result)
            return result

    except Exception as e:
        logger.error(f"VT error: {e}")

    return 0

# ===== GOOGLE SAFE BROWSING =====
def check_gsb(url: str) -> bool:
    cached = get_cache(f"gsb:{url}")
    if cached is not None:
        return cached

    if not GSB_KEY:
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}"

    payload = {
        "client": {"clientId": "spectarscan", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=3)
        flagged = resp.status_code == 200 and "matches" in resp.json()
        set_cache(f"gsb:{url}", flagged)
        return flagged

    except Exception as e:
        logger.error(f"GSB error: {e}")

    return False

@app.post("/predict")
@limiter.limit("10/minute")
async def predict(request: Request, body: URLRequest):

    try:
        # AUTH
        token = request.headers.get("x-api-key")
        if token != BACKEND_TOKEN:
            raise HTTPException(status_code=403, detail="Forbidden")

        url = body.url.lower().strip()
        signal = body.signal

        # CACHE WHOLE RESPONSE
        cached = get_cache(f"full:{url}")
        if cached:
            return cached

        impersonated = detect_clone(url)
        is_trusted = is_globally_trusted(url)
        live = get_domain_info(url)

        vt_hits = check_virustotal(url)
        gsb_flag = check_gsb(url)

        # ===== RISK ENGINE =====
        risk_score = 0
        reasons = []

        if vt_hits >= 5:
            risk_score += 70
            reasons.append("Malicious reputation")

        if gsb_flag:
            risk_score += 80
            reasons.append("Flagged by Google")

        if impersonated:
            risk_score += 60
            reasons.append(f"Impersonating {impersonated}")

        if live.get("age_days", 0) < 7:
            risk_score += 40
            reasons.append("New domain")

        if not live.get("is_ssl"):
            risk_score += 20
            reasons.append("No SSL")

        if not live.get("dns_resolves"):
            risk_score += 50
            reasons.append("DNS failure")

        if live.get("is_ip_hosting"):
            risk_score += 40
            reasons.append("IP hosting")

        if body.has_login_form:
            risk_score += 25

        if body.external_form_action:
            risk_score += 60

        if body.external_scripts > 2:
            risk_score += 20

        if signal == "credential_submit":
            risk_score += 100

        if is_trusted:
            risk_score -= 20

        risk_score = max(0, min(100, risk_score))

        if risk_score >= 80:
            verdict = "Dangerous"
        elif risk_score >= 40:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        response = {
            "url": url,
            "verdict": verdict,
            "risk_score": risk_score,
            "reasons": reasons[:3],
            "signals": {
                "vt_hits": vt_hits,
                "gsb_flag": gsb_flag,
                "domain_age": live.get("age_days"),
                "ssl": live.get("is_ssl")
            }
        }

        set_cache(f"full:{url}", response)

        return response

    except Exception as e:
        logger.error(f"Error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")


print("FINAL CLEAN VERSION RUNNING")