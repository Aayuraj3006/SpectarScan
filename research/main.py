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

app = FastAPI(title="SpecterScan Supreme Backend")

# ===== RATE LIMIT =====
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded. Please wait."})

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

# ===== ADVANCED CACHE =====
CACHE = {}
# Different TTLs to save API quota
TTL_MALICIOUS = 3600      # 1 Hour
TTL_SAFE = 86400         # 24 Hours
TTL_DEFAULT = 300        # 5 Minutes (for errors/unknowns)

def get_cache(key):
    if key in CACHE:
        data, timestamp, ttl = CACHE[key]
        if time.time() - timestamp < ttl:
            return data
        del CACHE[key]
    return None

def set_cache(key, value, ttl=TTL_DEFAULT):
    CACHE[key] = (value, time.time(), ttl)

# ===== REQUEST MODEL =====
class URLRequest(BaseModel):
    url: str
    signal: str | None = None
    has_login_form: bool = False
    external_form_action: bool = False
    external_scripts: int = 0

# ===== VIRUSTOTAL SCANNER =====
def check_virustotal(url: str) -> int:
    # 1. NORMALIZE: Remove spaces and trailing slashes
    url = url.strip().rstrip('/')
    
    cached = get_cache(f"vt:{url}")
    if cached is not None: return cached

    if not VT_KEY: 
        logger.error("VT_API_KEY is missing from environment variables!")
        return 0

    # 2. ENCODE: VT v3 needs Base64 WITHOUT padding (=)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_KEY}

    try:
        # Try to get the report
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        # 3. HANDLE 404: If not in database, request a scan
        if resp.status_code == 404:
            logger.info(f"URL not found in VT. Triggering fresh scan: {url}")
            requests.post(
                "https://www.virustotal.com/api/v3/urls",
                data={"url": url},
                headers=headers,
                timeout=10
            )
            # Return 1 to flag it as 'Suspicious' so it doesn't look 'Safe'
            return 1 

        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            hits = stats.get("malicious", 0)
            set_cache(f"vt:{url}", hits, TTL_MALICIOUS if hits > 0 else TTL_SAFE)
            return hits

        # 4. HANDLE AUTH ERROR: Check your Render Env Vars
        if resp.status_code == 401:
            logger.error("Invalid VT API Key! Check Render Dashboard.")

    except Exception as e:
        logger.error(f"VT API Request failed: {e}")
    
    return 0

# ===== GOOGLE SAFE BROWSING =====
def check_gsb(url: str) -> bool:
    cached = get_cache(f"gsb:{url}")
    if cached is not None: return cached

    if not GSB_KEY: return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}"
    payload = {
        "client": {"clientId": "specterscan", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        resp = requests.post(endpoint, json=payload, timeout=10)
        flagged = resp.status_code == 200 and "matches" in resp.json()
        set_cache(f"gsb:{url}", flagged, TTL_SAFE if not flagged else TTL_MALICIOUS)
        return flagged
    except Exception as e:
        logger.error(f"GSB API Error: {e}")
    return False

@app.post("/predict")
@limiter.limit("15/minute")
async def predict(request: Request, body: URLRequest):
    try:
        # AUTH CHECK
        token = request.headers.get("x-api-key")
        if token != BACKEND_TOKEN:
            raise HTTPException(status_code=403, detail="Unauthorized Access")

        url = body.url.lower().strip()
        
        # Check Full Response Cache
        cached_res = get_cache(f"full:{url}")
        if cached_res: return cached_res

        # Gather Signals
        impersonated = detect_clone(url)
        is_trusted = is_globally_trusted(url)
        live = get_domain_info(url)
        vt_hits = check_virustotal(url)
        gsb_flag = check_gsb(url)

        # ===== SUPREME RISK ENGINE =====
        risk_score = 0
        reasons = []

        # 1. VirusTotal Signals (Fixed Threshold)
        if vt_hits >= 3:
            risk_score += 85
            reasons.append(f"Flagged by {vt_hits} security engines")
        elif vt_hits >= 1:
            risk_score += 40
            reasons.append("Minor security engine flags")

        # 2. Google Blacklist
        if gsb_flag:
            risk_score += 90
            reasons.append("Google Safe Browsing Alert")

        # 3. Domain Age (Yellow Tag Support)
        age = live.get("age_days", 0)
        if age == 1:
            risk_score += 50
            reasons.append("Brand new domain (24h old)")
        elif 0 < age < 7:
            risk_score += 25
            reasons.append("Recently registered domain")

        # 4. Identity & Technicals
        if impersonated:
            risk_score += 70
            reasons.append(f"Potential spoof of {impersonated}")
        
        if not live.get("is_ssl") and not url.startswith("https"):
            risk_score += 30
            reasons.append("Unsecured (No SSL)")

        if live.get("is_ip_hosting"):
            risk_score += 45
            reasons.append("Hosting on raw IP address")

        # 5. Form Behavior
        if body.external_form_action:
            risk_score += 60
            reasons.append("Data exfiltration detected")

        # 6. Global Trust Override
        if is_trusted and vt_hits == 0:
            risk_score = 0
            reasons = []

        # FINAL CALCULATION
        risk_score = max(0, min(100, risk_score))

        if risk_score >= 75:
            verdict = "Dangerous"
        elif risk_score >= 35:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        response_data = {
            "url": url,
            "verdict": verdict,
            "risk_score": risk_score,
            "reasons": reasons[:3],
            "signals": {
                "vt_hits": vt_hits,
                "gsb_flag": gsb_flag,
                "domain_age": age,
                "ssl": live.get("is_ssl")
            }
        }

        # Cache the final verdict
        set_cache(f"full:{url}", response_data, TTL_SAFE if risk_score < 35 else TTL_MALICIOUS)

        return response_data

    except Exception as e:
        logger.error(f"Prediction Error: {e}")
        raise HTTPException(status_code=500, detail="Internal processing error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))