import re
import logging
import ipaddress
from urllib.parse import urlparse
from typing import Optional
from difflib import SequenceMatcher
import math
from collections import Counter

logger = logging.getLogger(__name__)

# ===== ENTROPY =====
def entropy(s: str) -> float:
    if not s:
        return 0
    prob = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in prob)


# ===== SUSPICIOUS TLDS =====
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "ga", "cf"]


# ===== PROTECTED BRANDS =====
PROTECTED_BRANDS = {
    "google.com": "Google",
    "facebook.com": "Facebook",
    "amazon.com": "Amazon",
    "paypal.com": "PayPal",
    "microsoft.com": "Microsoft",
    "apple.com": "Apple",
    "github.com": "GitHub"
}


# ===== TRUST CHECK =====
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


# ===== CLONE DETECTION =====
def detect_clone(url: str) -> Optional[str]:
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        domain = host.replace("www.", "")

        if is_globally_trusted(url):
            return None

        for brand_url, brand_name in PROTECTED_BRANDS.items():
            brand_root = brand_url.split('.')[0]

            similarity = SequenceMatcher(None, domain, brand_root).ratio()

            if similarity > 0.85:
                return brand_name

            if brand_root in domain:
                return brand_name

        return None
    except:
        return None


# ===== FEATURE EXTRACTION (OPTIONAL, SAFE) =====
def extract_features(url: str):
    features = []

    try:
        url = (url or "").lower().strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed = urlparse(url)
        host = parsed.hostname or ""

        # IP
        try:
            ipaddress.ip_address(host)
            features.append(-1)
        except:
            features.append(1)

        # Length
        features.append(1 if len(url) < 60 else (0 if len(url) < 100 else -1))

        # Shortener
        features.append(-1 if re.search(r"(bit\.ly|tinyurl|t\.co)", url) else 1)

        # @ symbol
        features.append(-1 if "@" in url else 1)

        # HTTPS
        features.append(1 if parsed.scheme == "https" else -1)

        # Entropy
        features.append(-1 if entropy(host) > 3.5 else 1)

        # Suspicious TLD
        tld = host.split(".")[-1] if "." in host else ""
        features.append(-1 if tld in SUSPICIOUS_TLDS else 1)

        while len(features) < 30:
            features.append(1)

        return features

    except Exception as e:
        logger.error(f"Feature extraction failed: {e}")
        return [1] * 30