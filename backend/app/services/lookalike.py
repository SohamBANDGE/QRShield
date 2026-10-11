"""Detect domains that imitate well-known brands."""
import re

from .common import finding, registered_domain, to_unicode_host

BRANDS = {
    "paytm": {"paytm.com", "paytm.in", "paytmbank.com"},
    "phonepe": {"phonepe.com"},
    "google": {"google.com", "google.co.in", "goo.gl", "g.co", "gstatic.com", "googleapis.com", "withgoogle.com"},
    "gpay": {"pay.google.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amzn.in", "amzn.to", "a.co"},
    "flipkart": {"flipkart.com", "fkrt.it"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbi.bank.in"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "kotak": {"kotak.com"},
    "npci": {"npci.org.in"},
    "bhimupi": {"bhimupi.org.in"},
    "irctc": {"irctc.co.in"},
    "uidai": {"uidai.gov.in"},
    "incometax": {"incometax.gov.in", "incometaxindia.gov.in"},
    "paypal": {"paypal.com", "paypal.me"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "facebook": {"facebook.com", "fb.com", "fb.me"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "netflix": {"netflix.com"},
    "swiggy": {"swiggy.com", "swiggy.in"},
    "zomato": {"zomato.com"},
}

# characters that are visually confusable with ASCII letters
CONFUSABLES = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
               "ѕ": "s", "ԁ": "d", "ӏ": "l", "ν": "v", "ο": "o", "ɡ": "g", "ı": "i"}


def skeleton(s: str) -> str:
    s = "".join(CONFUSABLES.get(ch, ch) for ch in s.lower())
    s = s.replace("rn", "m").replace("vv", "w")
    return s.translate(str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "5": "s"}))


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def check_lookalike(host: str) -> list[dict]:
    uhost = to_unicode_host(host)
    rd = registered_domain(uhost)
    if any(rd in legit or host in legit for legit in BRANDS.values()):
        return []
    label = rd.split(".")[0]
    tokens = [t for t in re.split(r"[-._]", uhost.rsplit(".", 1)[0]) if t]
    best = None
    for brand, legit in BRANDS.items():
        legit_hint = sorted(legit)[0]
        if label != brand and skeleton(label) == skeleton(brand):
            cand = (40, "Imitates " + brand, f"'{rd}' is spelled to look like {brand} but is not one of its domains (real: {legit_hint}).")
        elif len(brand) >= 5 and edit_distance(label, brand) == 1:
            cand = (35, "Looks like " + brand, f"'{rd}' is one character away from '{brand}'. Real site: {legit_hint}.")
        elif len(brand) >= 7 and edit_distance(label, brand) == 2:
            cand = (22, "Similar to " + brand, f"'{rd}' is a near-match for '{brand}'. Real site: {legit_hint}.")
        elif brand in tokens or (len(brand) >= 5 and brand in label):
            cand = (30, f"Uses the name '{brand}' on an unrelated site",
                    f"'{uhost}' contains '{brand}' but belongs to {rd}. Real site: {legit_hint}.")
        else:
            continue
        if best is None or cand[0] > best[0]:
            best = cand
    if best:
        return [finding("lookalike", "high", best[0], best[1], best[2], "domain")]
    return []
