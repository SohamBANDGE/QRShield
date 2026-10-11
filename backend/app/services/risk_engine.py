SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

VERDICTS = {
    "low": ("Low risk", "No strong warning signs were found. Checks can miss new scams, so stay alert when money or passwords are involved."),
    "suspicious": ("Suspicious", "Several warning signs found. Do not enter passwords, OTPs or payment details unless you can verify the source another way."),
    "dangerous": ("Dangerous", "Strong signs of phishing or fraud. Do not open this link or approve any payment."),
}


def level_for(score: int) -> str:
    return "dangerous" if score >= 60 else "suspicious" if score >= 25 else "low"


def build(findings: list[dict]):
    unique, seen = [], set()
    for f in findings:
        key = (f["id"], f["title"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    unique.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], -f["points"]))
    score = min(100, sum(f["points"] for f in unique))
    level = level_for(score)
    label, summary = VERDICTS[level]
    return {"score": score, "level": level, "verdict": label, "summary": summary, "reasons": unique}


def advice_for(level: str, kind: str) -> list[str]:
    tips = []
    if level == "dangerous":
        tips += ["Do not open the link or approve the payment.", "If it came as a sticker or poster, the code may have been pasted over the real one. Tell the owner."]
    elif level == "suspicious":
        tips += ["Go to the company's official app or website yourself instead of using this link.", "Never share an OTP, card PIN or UPI PIN on a page opened from a QR code."]
    else:
        tips += ["Check the address bar after the page opens and make sure it matches the brand you expect."]
    if kind == "upi":
        tips.append("You only enter your UPI PIN to pay. If someone says you will 'receive' money by scanning and entering a PIN, it is a scam.")
    if level != "low":
        tips.append("Report fraud to the National Cyber Crime Portal (cybercrime.gov.in) or call 1930.")
    return tips
