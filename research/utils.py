import re
import logging
import ipaddress
from urllib.parse import urlparse
from typing import Optional
from difflib import SequenceMatcher
import math
from collections import Counter

logger = logging.getLogger(__name__)

# --- ENTROPY ---
def entropy(s: str) -> float:
    if not s:
        return 0
    prob = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in prob)


# --- SUSPICIOUS TLDS ---
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf"]


# --- PROTECTED BRANDS ---
PROTECTED_BRANDS = {
    "google.com": "Google",
    "facebook.com": "Facebook",
    "amazon.com": "Amazon",
    "reddit.com": "Reddit",
    "wikipedia.org": "Wikipedia",
    "youtube.com": "YouTube",
    "netflix.com": "Netflix",
    "paypal.com": "PayPal",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "github.com": "GitHub",
    "chatgpt.com": "OpenAI/ChatGPT"
}


# --- TRUST CHECK ---
def is_globally_trusted(url: str) -> bool:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        domain = host.replace("www.", "")

        if domain in PROTECTED_BRANDS:
            return True

        parts = domain.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
            if root in PROTECTED_BRANDS:
                return True

        return False
    except:
        return False


# --- STRONG CLONE DETECTION ---
def detect_clone(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        domain = host.replace("www.", "")

        if is_globally_trusted(url):
            return None

        for brand_url, brand_name in PROTECTED_BRANDS.items():
            brand_root = brand_url.split('.')[0]

            # Check entire domain (not just first part)
            similarity = SequenceMatcher(None, domain, brand_root).ratio()

            if similarity > 0.75:
                return brand_name

            # Hidden brand keyword inside domain
            if brand_root in domain:
                return brand_name

        return None
    except:
        return None


# --- FEATURE EXTRACTION ---
def extract_features(url: str):

    features = []

    try:
        url = (url or "").lower().strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        host = parsed.hostname or ""
        domain = host

        # 1. IP
        try:
            ipaddress.ip_address(domain)
            features.append(-1)
        except:
            features.append(1)

        # 2. URL length
        length = len(url)
        features.append(1 if length < 60 else (0 if length < 100 else -1))

        # 3. Shorteners
        features.append(-1 if re.search(r"(bit\.ly|tinyurl|t\.co|goo\.gl)", url) else 1)

        # 4. @ symbol
        features.append(-1 if "@" in url else 1)

        # 5. Redirect
        features.append(-1 if url.rfind("//") > 7 else 1)

        # 6. Hyphen
        features.append(-1 if "-" in domain else 1)

        # 7. Subdomains
        dots = domain.count(".")
        features.append(1 if dots <= 2 else (0 if dots == 3 else -1))

        # 8. HTTPS
        features.append(1 if parsed.scheme == "https" else -1)

        # --- ADVANCED FEATURES ---

        # 9. Domain entropy
        features.append(-1 if entropy(domain) > 3.5 else 1)

        # 10. Full URL entropy
        features.append(-1 if entropy(url) > 4.5 else 1)

        # 11. Suspicious TLD
        tld = domain.split(".")[-1] if "." in domain else ""
        features.append(-1 if tld in SUSPICIOUS_TLDS else 1)

        # 12. Digit ratio
        digits = sum(c.isdigit() for c in domain)
        ratio = digits / len(domain) if domain else 0
        features.append(-1 if ratio > 0.3 else 1)

        # 13. Suspicious keywords (expanded)
        keywords = [
            "login", "secure", "verify", "account", "update",
            "bank", "signin", "confirm", "password", "auth"
        ]
        features.append(-1 if any(k in url for k in keywords) else 1)

        # 14. Long path
        features.append(-1 if len(parsed.path) > 50 else 1)

        # 15. Multiple subdomain levels
        features.append(-1 if domain.count('.') > 3 else 1)

        # Fill to 30
        while len(features) < 30:
            features.append(1)

        return features

    except Exception as e:
        logger.error(f"Feature extraction failed: {e}")
        return [1] * 30