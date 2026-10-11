"""Follow redirects hop by hop without downloading page bodies or running scripts."""
from urllib.parse import urljoin, urlparse

import httpx

from .common import finding, is_public_host, registered_domain

DOWNLOAD_TYPES = ("application/vnd.android.package-archive", "application/x-msdownload",
                  "application/octet-stream", "application/x-dosexec")
USER_AGENT = "Mozilla/5.0 (compatible; QRShield-Scanner/1.0)"


def trace(url: str, max_hops: int = 6, timeout: float = 5.0) -> dict:
    hops, current, error, ctype = [], url, None, None
    with httpx.Client(follow_redirects=False, timeout=timeout, headers={"User-Agent": USER_AGENT}) as client:
        for _ in range(max_hops + 1):
            p = urlparse(current)
            if p.scheme not in ("http", "https") or not p.hostname:
                error = "Redirected to a non-web address"
                hops.append({"url": current, "status": None, "note": error})
                break
            ok, why = is_public_host(p.hostname)
            if not ok:
                error = why
                hops.append({"url": current, "status": None, "note": why})
                break
            try:
                with client.stream("GET", current) as r:  # headers only; body is never read
                    status, location, ctype = r.status_code, r.headers.get("location"), r.headers.get("content-type", "")
            except httpx.HTTPError as e:
                error = f"Could not reach the site ({type(e).__name__})"
                hops.append({"url": current, "status": None, "note": error})
                break
            hops.append({"url": current, "status": status})
            if status in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                continue
            break
        else:
            error = "Too many redirects"
    return {"hops": hops, "final_url": hops[-1]["url"] if hops else url, "error": error, "content_type": ctype}


def trace_findings(result: dict, original_url: str) -> list[dict]:
    out = []
    redirects = max(0, len(result["hops"]) - 1)
    if redirects >= 3:
        out.append(finding("many_redirects", "medium", 10, f"Redirects {redirects} times",
                           "Long redirect chains are used to hide where you end up.", "redirect"))
    elif result["error"] == "Too many redirects":
        out.append(finding("redirect_loop", "medium", 12, "Endless redirects", "The link keeps bouncing between pages.", "redirect"))
    start = registered_domain(urlparse(original_url).hostname or "")
    end = registered_domain(urlparse(result["final_url"]).hostname or "")
    if start and end and start != end and redirects:
        out.append(finding("cross_domain", "low", 6, "Ends up on a different website",
                           f"You scan {start} but land on {end}.", "redirect"))
    if (result.get("content_type") or "").lower().startswith(DOWNLOAD_TYPES):
        out.append(finding("download_type", "high", 25, "Destination serves a file download",
                           "The link triggers a download instead of showing a web page.", "redirect"))
    if result["error"] and result["error"].startswith("Points to a private"):
        out.append(finding("internal_target", "high", 20, "Link points inside a private network",
                           result["error"] + ". Legitimate public QR codes do not do this.", "redirect"))
    return out
