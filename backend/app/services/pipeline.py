"""Orchestrates every check and assembles the explainable report."""
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from ..config import settings
from . import domain_intel, redirect_tracer, risk_engine, threat_intel
from .common import finding, is_ip, registered_domain
from .lookalike import check_lookalike
from .upi_parser import parse_upi
from .url_analyzer import analyze_url

URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']+", re.I)
BARE_DOMAIN = re.compile(r"^[a-z0-9][a-z0-9\-._]*\.[a-z]{2,}(:\d+)?(/\S*)?$", re.I)
RISKY_SCHEMES = {
    "javascript": (60, "Code that runs in your browser"),
    "data": (50, "Embedded content instead of a website"),
    "file": (40, "Opens a file on your device"),
    "intent": (30, "Launches an app on Android"),
    "market": (15, "Opens an app store listing"),
}


def classify(payload: str):
    low = payload.lower()
    if low.startswith("upi:"):
        return "upi", payload
    if re.match(r"^https?://", low):
        return "url", payload
    if BARE_DOMAIN.match(payload):
        return "url", "https://" + payload
    return "text", payload


def _inspect_url(url: str, deep: bool, prefix: str = ""):
    """Lexical + lookalike + (optionally) network checks for one URL."""
    host = (urlparse(url).hostname or "").lower()
    rd = registered_domain(host)
    findings = analyze_url(url)
    if host and not is_ip(host):
        findings += check_lookalike(host)
    details = {"host": host, "registered_domain": rd, "domain_age_days": None, "ssl": None, "threat_intel": {}}
    if deep and host:
        with ThreadPoolExecutor(max_workers=3) as ex:
            f_age = ex.submit(domain_intel.get_domain_age_days, rd) if not is_ip(host) else None
            f_ssl = ex.submit(domain_intel.get_ssl_info, host) if url.startswith("https") else None
            f_ti = ex.submit(threat_intel.check, url)
            details["domain_age_days"] = f_age.result() if f_age else None
            details["ssl"] = f_ssl.result() if f_ssl else None
            ti_findings, details["threat_intel"] = f_ti.result()
        findings += domain_intel.age_findings(details["domain_age_days"])
        findings += domain_intel.ssl_findings(details["ssl"] or {})
        findings += ti_findings
    if prefix:
        for f in findings:
            f["title"] = prefix + f["title"]
    return findings, details


def analyze_payload(raw: str, deep=None) -> dict:
    deep = settings.enable_network if deep is None else deep
    payload = (raw or "").strip()
    if not payload:
        raise ValueError("Nothing to analyse.")
    if len(payload) > 2048:
        raise ValueError("That content is too long to be a normal QR code or link.")

    kind, value = classify(payload)
    findings, details = [], {}
    skipped = [] if deep else ["domain age", "certificate", "redirect trace", "threat feeds"]

    if kind == "url":
        if deep:
            with ThreadPoolExecutor(max_workers=2) as ex:
                f_main = ex.submit(_inspect_url, value, True)
                f_trace = ex.submit(redirect_tracer.trace, value)
                findings, details = f_main.result()
                trace = f_trace.result()
            findings += redirect_tracer.trace_findings(trace, value)
            details["redirect_chain"] = trace["hops"]
            details["final_url"] = trace["final_url"]
            if trace["error"]:
                details["trace_note"] = trace["error"]
            final_host = urlparse(trace["final_url"]).hostname or ""
            if final_host and final_host != details["host"] and not trace["error"]:
                f2, d2 = _inspect_url(trace["final_url"], True, "After redirect: ")
                findings += f2
                details["final"] = d2
        else:
            findings, details = _inspect_url(value, False)
            details["redirect_chain"], details["final_url"] = [], value
        if not any(v not in ("skipped",) for v in details.get("threat_intel", {}).values()) and deep:
            skipped.append("threat feeds (no API keys set)")

    elif kind == "upi":
        upi, findings = parse_upi(value)
        details["upi"] = upi

    else:
        scheme = value.split(":", 1)[0].lower() if ":" in value[:12] else ""
        embedded = URL_IN_TEXT.search(value)
        if scheme in RISKY_SCHEMES:
            pts, why = RISKY_SCHEMES[scheme]
            findings.append(finding("risky_scheme", "high" if pts >= 40 else "medium", pts, f"Unusual code type ({scheme}:)", why + ".", "text"))
        elif embedded:
            findings, details = _inspect_url(embedded.group(0), deep)
            findings.append(finding("embedded_url", "info", 0, "Link found inside text", embedded.group(0), "text"))
            kind = "url"
            value = embedded.group(0)
        else:
            what = {"wifi": "Wi-Fi login", "tel": "phone number", "sms": "text message", "smsto": "text message",
                    "mailto": "email", "begin": "contact card"}.get(scheme, "plain text")
            findings.append(finding("not_link", "info", 0, f"This code contains {what}, not a website",
                                    "No link to check. Read the content before acting on it.", "text"))
            if scheme == "wifi":
                findings.append(finding("wifi_note", "low", 5, "Joining a Wi-Fi network from a code",
                                        "Only join networks you trust. Open networks can expose your traffic.", "text"))

    report = risk_engine.build(findings)
    report.update({
        "input": {"kind": kind, "value": value},
        "details": details,
        "advice": risk_engine.advice_for(report["level"], kind),
        "confidence": "full" if deep else "limited",
        "skipped_checks": skipped,
    })
    return report
