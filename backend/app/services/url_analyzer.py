"""Lexical checks: things you can tell from the URL string alone."""
import re
from urllib.parse import urlparse, unquote

from .common import finding, is_ip, registered_domain

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "shorturl.at",
              "ow.ly", "tiny.cc", "rebrand.ly", "t.ly", "buff.ly", "qrco.de", "q.me-qr.com", "l.ead.me"}
RISKY_TLDS = {"zip", "mov", "top", "xyz", "click", "tk", "gq", "ml", "cf", "ga", "icu", "monster",
              "rest", "cyou", "sbs", "cfd", "buzz", "country", "support"}
KEYWORDS = ["login", "signin", "verify", "verification", "update", "secure", "account", "kyc", "reward",
            "claim", "bonus", "prize", "refund", "wallet", "suspend", "suspended", "otp", "password",
            "free", "gift", "cashback", "lottery", "winner", "urgent", "confirm", "unlock", "banking"]
DANGEROUS_EXT = (".apk", ".exe", ".scr", ".msi", ".bat", ".cmd", ".jar", ".vbs", ".ps1", ".dmg", ".pkg")


def analyze_url(url: str) -> list[dict]:
    out = []
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return [finding("malformed", "medium", 15, "Malformed link",
                        "The link is not a valid URL, which is unusual for a legitimate code.", "url")]
    if not host:
        return [finding("no_host", "medium", 15, "Link has no domain", "Nothing to check the destination against.", "url")]

    rd = registered_domain(host)

    if p.scheme == "http":
        out.append(finding("no_https", "low", 10, "Not encrypted (http)",
                           "The page loads without HTTPS, so anything you type can be read in transit.", "url"))
    if is_ip(host):
        out.append(finding("ip_host", "high", 25, "Link points to a raw IP address",
                           "Legitimate services almost always use a named domain, not a bare IP.", "url"))
    if p.username or p.password or "@" in (p.netloc or ""):
        out.append(finding("userinfo", "high", 25, "Hidden destination using '@'",
                           "Text before the '@' is ignored by the browser and is often used to disguise the real site.", "url"))
    if "xn--" in host:
        out.append(finding("punycode", "high", 20, "Look-alike characters in the domain",
                           "The domain uses punycode (xn--), a trick used to imitate brand names with foreign letters.", "url"))
    if len(url) > 100:
        out.append(finding("long_url", "low", 8, "Very long link", f"{len(url)} characters. Scam links often hide intent in long strings.", "url"))
    elif len(url) > 75:
        out.append(finding("long_url", "low", 4, "Long link", f"{len(url)} characters.", "url"))

    if not is_ip(host):
        sub_labels = host[: -len(rd)].strip(".").split(".") if host != rd and host.endswith(rd) else []
        if len([s for s in sub_labels if s]) >= 3:
            out.append(finding("deep_subdomain", "medium", 10, "Many subdomains",
                               f"'{host}' stacks several subdomains in front of {rd}. The part that matters is {rd}.", "url"))
        tld = host.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS:
            out.append(finding("risky_tld", "medium", 12, f"Uncommon domain ending (.{tld})",
                               "This ending is cheap and heavily used for throwaway scam sites.", "url"))
        if host.split(".")[0].count("-") >= 3 or rd.split(".")[0].count("-") >= 3:
            out.append(finding("many_hyphens", "low", 8, "Many hyphens in the domain",
                               "Names like 'secure-login-update-bank' are a common phishing pattern.", "url"))
        if sum(ch.isdigit() for ch in rd.split(".")[0]) >= 4:
            out.append(finding("many_digits", "low", 6, "Many digits in the domain", "Random digits suggest an auto-generated domain.", "url"))
    if rd in SHORTENERS or host in SHORTENERS:
        out.append(finding("shortener", "medium", 12, "Link shortener hides the real destination",
                           "The final site is unknown until the link is followed. See the redirect trace below.", "url"))
    if port and port not in (80, 443):
        out.append(finding("odd_port", "low", 8, f"Unusual port ({port})", "Legitimate sites rarely use non-standard ports.", "url"))

    haystack = unquote(f"{host}{p.path}?{p.query}").lower()
    hits = sorted({k for k in KEYWORDS if k in haystack})
    if hits:
        pts = min(18, 6 * len(hits))
        out.append(finding("keywords", "medium" if pts >= 12 else "low", pts, "Pressure or credential words in the link",
                           "Contains: " + ", ".join(hits) + ". Scams use these to prompt a quick login or payment.", "url"))
    if re.search(r"%25[0-9a-fA-F]{2}", url):
        out.append(finding("double_encoding", "medium", 8, "Double-encoded characters", "Encoding tricks can hide the true address.", "url"))
    if p.path.lower().endswith(DANGEROUS_EXT):
        ext = p.path.lower().rsplit(".", 1)[-1]
        out.append(finding("download", "high", 30, f"Link downloads a .{ext} file",
                           "A QR code that installs an app or program directly is a major red flag.", "url"))
    return out
