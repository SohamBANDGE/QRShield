"""Analyse upi:// payment QR codes."""
import re
from urllib.parse import parse_qs, urlparse

from .common import finding

VPA_RE = re.compile(r"^[A-Za-z0-9.\-_]{2,256}@[A-Za-z]{2,64}$")
BAIT_WORDS = ["refund", "cashback", "receive", "reward", "prize", "lottery", "claim", "bonus", "gift", "winner"]


def parse_upi(uri: str):
    p = urlparse(uri)
    q = {k: v[0] for k, v in parse_qs(p.query).items()}
    action = (p.netloc or p.path.strip("/")).lower()
    details = {
        "action": action,
        "payee_vpa": q.get("pa"),
        "payee_name": q.get("pn"),
        "amount": q.get("am"),
        "currency": q.get("cu", "INR"),
        "note": q.get("tn"),
        "merchant_code": q.get("mc"),
    }
    out = []
    pa = details["payee_vpa"]
    if not pa:
        out.append(finding("upi_no_payee", "high", 30, "No payee in this payment code", "A valid UPI code always names who gets the money.", "upi"))
    elif not VPA_RE.match(pa):
        out.append(finding("upi_bad_vpa", "medium", 20, "Payee ID looks malformed", f"'{pa}' is not a valid UPI address.", "upi"))
    if action == "collect":
        out.append(finding("upi_collect", "high", 40, "This is a money request, not a receipt",
                           "Approving it sends money out of your account.", "upi"))
    note_text = f"{details['note'] or ''} {details['payee_name'] or ''}".lower()
    bait = [w for w in BAIT_WORDS if w in note_text]
    if bait:
        out.append(finding("upi_bait", "high", 35, "Payment note promises money",
                           f"Mentions {', '.join(bait)}. Scammers say you will 'receive' money, but scanning a payment QR always sends it.", "upi"))
    try:
        amt = float(details["amount"]) if details["amount"] else None
    except ValueError:
        amt = None
        out.append(finding("upi_bad_amount", "medium", 10, "Amount is not a number", f"Amount field: '{details['amount']}'.", "upi"))
    if amt is not None:
        sev, pts = ("medium", 10) if amt >= 10000 else ("info", 0)
        out.append(finding("upi_amount", sev, pts, f"Pre-filled amount: {details['currency']} {amt:,.2f}",
                           "Check this amount matches what you owe before entering your PIN.", "upi"))
    if pa and VPA_RE.match(pa):
        out.append(finding("upi_payee", "info", 0, f"You would pay {details['payee_name'] or 'an unnamed payee'}",
                           f"Payee ID: {pa}. Confirm the name matches the shop or person.", "upi"))
    return details, out
