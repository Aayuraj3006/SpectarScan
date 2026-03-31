import logging
import whois
from datetime import datetime
import socket
from urllib.parse import urlparse
import ipaddress
import ssl

logger = logging.getLogger(__name__)


def _parse_date(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, list) and value:
        return _parse_date(value[0])
    if isinstance(value, str):
        clean_val = value.split(' ')[0].strip()
        for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d", "%Y.%m.%d"):
            try:
                return datetime.strptime(clean_val, fmt)
            except:
                continue
    return None


def _normalize_host(url):
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or parsed.netloc.split(":")[0] or ""
        host = host.lower()
        if host.startswith("www."):
            host = host[4:]
        return host
    except:
        return ""


def get_domain_info(url):
    host = _normalize_host(url)

    info = {
        "domain": host,
        "age_days": 0,
        "is_ssl": False,
        "registrar": "Unknown",
        "ip_address": "Unknown",
        "is_reputable_registrar": False,
        "dns_resolves": True,           # ✅ NEW
        "is_ip_hosting": False          # ✅ NEW
    }

    if not host:
        return info

    # --- 1. DNS / IP ---
    try:
        ip = socket.gethostbyname(host)
        info["ip_address"] = ip

        # Check if it's direct IP hosting
        try:
            ipaddress.ip_address(host)
            info["is_ip_hosting"] = True
        except:
            info["is_ip_hosting"] = False

    except:
        info["dns_resolves"] = False

    # --- 2. WHOIS ---
    try:
        ipaddress.ip_address(host)
        info["registrar"] = "Direct IP"
    except:
        try:
            w = whois.whois(host)

            created = _parse_date(w.creation_date)
            if created:
                created = created.replace(tzinfo=None)
                info["age_days"] = (datetime.now() - created).days

            registrar = str(getattr(w, "registrar", "Unknown"))
            info["registrar"] = registrar

            trusted_providers = [
                "markmonitor",
                "csc corporate",
                "amazon",
                "google",
                "godaddy",
                "namecheap"
            ]

            reg_lower = registrar.lower()
            info["is_reputable_registrar"] = any(
                p in reg_lower for p in trusted_providers
            )

        except Exception as e:
            logger.debug(f"WHOIS failed for {host}: {e}")

    # --- 3. SSL CHECK (Improved) ---
    try:
        context = ssl.create_default_context()

        with socket.create_connection((host, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                # SSL exists
                info["is_ssl"] = True

                # Optional: certificate expiry check
                if "notAfter" in cert:
                    try:
                        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        if expiry < datetime.utcnow():
                            info["is_ssl"] = False
                    except:
                        pass

    except:
        info["is_ssl"] = False

    return info