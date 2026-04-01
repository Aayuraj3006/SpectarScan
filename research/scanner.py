import logging
import whois
from datetime import datetime
import socket
from urllib.parse import urlparse
import ipaddress
import ssl
import threading

logger = logging.getLogger(__name__)


def _parse_date(value):
    if isinstance(value, datetime):
        return value
    if isinstance(value, list) and value:
        return _parse_date(value[0])
    return None


def _normalize_host(url):
    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = parsed.hostname or ""
        if host.startswith("www."):
            host = host[4:]
        return host.lower()
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
        "dns_resolves": True,
        "is_ip_hosting": False
    }

    if not host:
        return info

    # ===== DNS / IP =====
    try:
        ip = socket.gethostbyname(host)
        info["ip_address"] = ip

        try:
            ipaddress.ip_address(host)
            info["is_ip_hosting"] = True
        except:
            info["is_ip_hosting"] = False

    except:
        info["dns_resolves"] = False

    # ===== WHOIS (with timeout) =====
    def whois_lookup():
        try:
            w = whois.whois(host)

            created = _parse_date(w.creation_date)
            if created:
                created = created.replace(tzinfo=None)
                info["age_days"] = (datetime.now() - created).days

            registrar = str(getattr(w, "registrar", "Unknown"))
            info["registrar"] = registrar

            trusted = ["google", "amazon", "godaddy", "namecheap"]
            info["is_reputable_registrar"] = any(t in registrar.lower() for t in trusted)

        except Exception as e:
            logger.debug(f"WHOIS failed: {e}")

    try:
        t = threading.Thread(target=whois_lookup)
        t.start()
        t.join(timeout=3)
    except:
        pass

    # ===== SSL CHECK =====
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                info["is_ssl"] = True
    except:
        info["is_ssl"] = False

    return info