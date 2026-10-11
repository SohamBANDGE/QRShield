"""Network-based domain checks: registration age and TLS certificate."""
import socket
import ssl
import time
from datetime import datetime, timezone

from .common import finding, is_public_host


def get_domain_age_days(domain: str):
    try:
        import whois
    except ImportError:
        return None
    try:
        created = whois.whois(domain).creation_date
        if isinstance(created, list):
            created = min(c for c in created if c)
        if not created:
            return None
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - created).days)
    except Exception:
        return None


def get_ssl_info(host: str, port: int = 443, timeout: float = 4.0) -> dict:
    ok, why = is_public_host(host)
    if not ok:
        return {"error": why}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        now = time.time()
        return {
            "valid": True,
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "issued_days_ago": int((now - ssl.cert_time_to_seconds(cert["notBefore"])) / 86400),
            "expires_in_days": int((ssl.cert_time_to_seconds(cert["notAfter"]) - now) / 86400),
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": e.verify_message}
    except (OSError, ssl.SSLError):
        return {"error": "No HTTPS connection available"}


def age_findings(age_days) -> list[dict]:
    if age_days is None:
        return []
    if age_days < 30:
        return [finding("domain_new", "high", 30, "Domain registered very recently",
                        f"Registered {age_days} day(s) ago. Most scam sites are under a month old.", "domain")]
    if age_days < 90:
        return [finding("domain_young", "medium", 18, "Domain is only a few months old", f"Registered {age_days} days ago.", "domain")]
    if age_days < 365:
        return [finding("domain_year", "low", 6, "Domain is less than a year old", f"Registered {age_days} days ago.", "domain")]
    return [finding("domain_old", "info", 0, "Established domain", f"Registered about {age_days // 365} year(s) ago.", "domain")]


def ssl_findings(info: dict) -> list[dict]:
    if info.get("valid") is False:
        return [finding("ssl_invalid", "high", 25, "Invalid security certificate",
                        f"The site's HTTPS certificate failed verification: {info.get('error', 'unknown error')}.", "domain")]
    if info.get("valid") and info.get("issued_days_ago", 999) <= 7:
        return [finding("ssl_fresh", "low", 5, "Certificate issued within the last week",
                        "Common for brand-new scam sites, though legitimate sites renew too.", "domain")]
    return []
