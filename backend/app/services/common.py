import ipaddress
import socket

MULTI_PART_TLDS = {
    "co.in", "org.in", "net.in", "gov.in", "ac.in", "nic.in", "res.in", "edu.in",
    "co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "com.br", "co.za", "com.sg", "com.pk",
}


def finding(fid, severity, points, title, detail, category):
    """One line item in the risk report. severity: info | low | medium | high."""
    return {"id": fid, "severity": severity, "points": points, "title": title,
            "detail": detail, "category": category}


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    host = host.lower().strip(".")
    if is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def to_unicode_host(host: str) -> str:
    """Decode punycode labels so lookalike checks can see the real characters."""
    try:
        return host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return host


def is_public_host(host: str):
    """SSRF guard: every resolved address must be globally routable."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "Domain does not resolve"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            return False, f"Points to a private or internal address ({ip})"
    return True, ""
