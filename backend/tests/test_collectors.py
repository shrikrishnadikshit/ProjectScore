from datetime import datetime, timedelta, timezone

from app.collectors import dns_health, email, tls, web


def codes(findings):
    return {x.code for x in findings}


def test_spf():
    assert codes(email.evaluate_spf("a.com", [])) == {"spf_missing"}
    assert codes(email.evaluate_spf("a.com", ["v=spf1 +all"])) == {"spf_pass_all"}
    assert codes(email.evaluate_spf("a.com", ["v=spf1 include:x ?all"])) == {"spf_weak"}
    assert email.evaluate_spf("a.com", ["v=spf1 include:_spf.google.com -all", "google-site-verification=x"]) == []


def test_dmarc():
    assert codes(email.evaluate_dmarc("a.com", [])) == {"dmarc_missing"}
    assert codes(email.evaluate_dmarc("a.com", ["v=DMARC1; p=none; rua=mailto:x@a.com"])) == {"dmarc_monitor_only"}
    assert codes(email.evaluate_dmarc("a.com", ["v=DMARC1; p=quarantine; pct=50"])) == {"dmarc_partial"}
    assert email.evaluate_dmarc("a.com", ["v=DMARC1; p=reject"]) == []


def test_dangling_cname():
    assert codes(dns_health.evaluate_dangling_cname("shop.a.com", "gone.herokuapp.com", False)) == {"dangling_cname"}
    assert dns_health.evaluate_dangling_cname("shop.a.com", "live.cdn.net", True) == []


def test_certificate():
    now = datetime(2026, 12, 1, tzinfo=timezone.utc)
    assert codes(tls.evaluate_certificate("a.com", now - timedelta(days=1), True, "TLSv1.3", now)) == {"cert_expired"}
    assert codes(tls.evaluate_certificate("a.com", now + timedelta(days=5), True, "TLSv1.2", now)) == {"cert_expiring"}
    assert codes(tls.evaluate_certificate("a.com", None, False, None, now)) == {"cert_untrusted"}
    assert codes(tls.evaluate_certificate("a.com", now + timedelta(days=90), True, "TLSv1.1", now)) == {"tls_old_protocol"}


def test_headers():
    found = web.evaluate_headers("a.com", {}, ["sid=1; Path=/"])
    assert {"hsts_missing", "csp_missing", "xfo_missing", "cookie_flags"} <= codes(found)
    good = {"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff"}
    assert web.evaluate_headers("a.com", good, ["sid=1; Secure; HttpOnly"]) == []
