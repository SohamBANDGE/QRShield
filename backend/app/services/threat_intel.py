"""Optional lookups against public threat-intelligence feeds. Every source is skipped without a key."""
import base64

import httpx

from .. import database as db
from ..config import settings
from .common import finding

TIMEOUT = 6.0


def _cached(key, fn):
    hit = db.cache_get(key)
    if hit is not None:
        return hit
    value = fn()
    if value.get("status") != "error":
        db.cache_set(key, value)
    return value


def _google_safe_browsing(url):
    body = {
        "client": {"clientId": "qrshield", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}],
        },
    }
    try:
        r = httpx.post("https://safebrowsing.googleapis.com/v4/threatMatches:find",
                       params={"key": settings.gsb_api_key}, json=body, timeout=TIMEOUT)
        r.raise_for_status()
        matches = r.json().get("matches", [])
        if matches:
            return {"status": "flagged", "detail": ", ".join(sorted({m["threatType"].replace("_", " ").title() for m in matches}))}
        return {"status": "clean"}
    except Exception:
        return {"status": "error"}


def _virustotal(url):
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = httpx.get(f"https://www.virustotal.com/api/v3/urls/{uid}",
                      headers={"x-apikey": settings.vt_api_key}, timeout=TIMEOUT)
        if r.status_code == 404:
            return {"status": "unknown"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"status": "flagged" if stats.get("malicious", 0) or stats.get("suspicious", 0) >= 2 else "clean",
                "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)}
    except Exception:
        return {"status": "error"}


def _urlhaus(url):
    try:
        r = httpx.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                       headers={"Auth-Key": settings.urlhaus_key}, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "ok":
            return {"status": "flagged", "detail": data.get("threat") or "malware distribution"}
        return {"status": "clean"}
    except Exception:
        return {"status": "error"}


def check(url: str):
    """Returns (findings, per-source status dict)."""
    sources = {}
    jobs = [("google_safe_browsing", settings.gsb_api_key, _google_safe_browsing),
            ("virustotal", settings.vt_api_key, _virustotal),
            ("urlhaus", settings.urlhaus_key, _urlhaus)]
    for name, key, fn in jobs:
        sources[name] = _cached(f"{name}:{url}", lambda fn=fn: fn(url)) if key else {"status": "skipped"}

    out = []
    gsb = sources["google_safe_browsing"]
    if gsb["status"] == "flagged":
        out.append(finding("ti_gsb", "high", 70, "Google Safe Browsing flags this link",
                           f"Listed for: {gsb.get('detail', 'unsafe content')}.", "threat_intel"))
    vt = sources["virustotal"]
    if vt["status"] == "flagged":
        m = vt.get("malicious", 0)
        out.append(finding("ti_vt", "high", 70 if m >= 3 else 35, f"VirusTotal: {m} engines flag this link",
                           f"{m} malicious and {vt.get('suspicious', 0)} suspicious verdicts from security vendors.", "threat_intel"))
    uh = sources["urlhaus"]
    if uh["status"] == "flagged":
        out.append(finding("ti_urlhaus", "high", 70, "Listed on URLhaus", f"Reported for: {uh.get('detail')}.", "threat_intel"))
    return out, {k: v["status"] for k, v in sources.items()}
