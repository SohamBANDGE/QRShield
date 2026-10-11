from app.services.pipeline import analyze_payload
from app.services.lookalike import check_lookalike
from app.services.url_analyzer import analyze_url
from app.services.upi_parser import parse_upi


def ids(findings):
    return {f["id"] for f in findings}


def test_clean_known_site_is_low_risk():
    r = analyze_payload("https://www.google.com/maps", deep=False)
    assert r["level"] == "low" and r["score"] < 25


def test_homoglyph_brand():
    assert "lookalike" in ids(check_lookalike("paytrn.com"))


def test_one_char_typo():
    assert "lookalike" in ids(check_lookalike("amazonn.in"))


def test_brand_in_subdomain_of_other_site():
    assert "lookalike" in ids(check_lookalike("paytm.secure-verify.xyz"))


def test_real_brand_domain_not_flagged():
    assert check_lookalike("accounts.google.com") == []
    assert check_lookalike("www.onlinesbi.sbi") == []


def test_ip_and_userinfo():
    f = ids(analyze_url("http://paytm.com@192.168.4.2/login"))
    assert {"ip_host", "userinfo", "no_https", "keywords"} <= f


def test_phishing_style_url_is_dangerous():
    r = analyze_payload("http://paytm-kyc-verify-update.xyz/login?claim=reward", deep=False)
    assert r["level"] in ("suspicious", "dangerous") and r["score"] >= 40


def test_apk_download():
    assert "download" in ids(analyze_url("https://example.com/app/offer.apk"))


def test_upi_collect_and_bait():
    _, f = parse_upi("upi://collect?pa=abc@okaxis&pn=Cashback%20Reward&am=5000&tn=claim%20refund")
    assert {"upi_collect", "upi_bait"} <= ids(f)


def test_plain_upi_is_info_only():
    r = analyze_payload("upi://pay?pa=shop@okicici&pn=Sharma%20Store&am=120", deep=False)
    assert r["level"] == "low"


def test_text_payload_and_bare_domain():
    assert analyze_payload("WIFI:S:Cafe;T:WPA;P:pass;;", deep=False)["input"]["kind"] == "text"
    assert analyze_payload("example.com/menu", deep=False)["input"]["kind"] == "url"


def test_javascript_scheme_blocked():
    assert analyze_payload("javascript:alert(1)", deep=False)["level"] == "dangerous"


def test_empty_rejected():
    import pytest
    with pytest.raises(ValueError):
        analyze_payload("   ", deep=False)
