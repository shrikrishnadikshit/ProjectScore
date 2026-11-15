import base64

from app.collectors import email, lookalike

KEY_1024 = base64.b64encode(b"\x30" * 162).decode()
KEY_2048 = base64.b64encode(b"\x30" * 294).decode()
KEY_512 = base64.b64encode(b"\x30" * 94).decode()


def codes(fs):
    return [f.code for f in fs]


def test_dkim_key_sizes():
    assert email.dkim_key_bits(f"v=DKIM1; k=rsa; p={KEY_2048}") == 2048
    assert email.dkim_key_bits(f"v=DKIM1; p={KEY_1024}") == 1024
    assert email.dkim_key_bits("v=DKIM1; p=") == 0
    assert email.dkim_key_bits("v=DKIM1; k=ed25519; p=abc") is None


def test_dkim_findings():
    assert codes(email.evaluate_dkim("a.example", {})) == ["dkim_not_found"]
    assert email.evaluate_dkim("a.example", {})[0].detection_confidence == 0.5
    assert codes(email.evaluate_dkim("a.example", {"s1": f"v=DKIM1; p={KEY_512}"})) == ["dkim_weak_key"]
    assert codes(email.evaluate_dkim("a.example", {"s1": f"v=DKIM1; p={KEY_1024}"})) == ["dkim_1024"]
    assert email.evaluate_dkim("a.example", {"s1": f"v=DKIM1; p={KEY_1024}", "s2": f"p={KEY_2048}"}) == []


def test_lookalike_candidates():
    c = lookalike.candidates("acmebank.com")
    for d in ("acmbank.com", "acmeebank.com", "camebank.com", "acrnebank.com", "acme-bank.com",
              "acmebank.in", "acmebank.co.in", "acmebank-login.com", "acmebamk.com", "acmeb4nk.com"):
        assert d in c, d
    assert "acmebank.com" not in c and len(c) <= lookalike.MAX_CANDIDATES
    assert lookalike.split_domain("acme.co.in") == ("acme", "co.in")
    assert "acme.com" in lookalike.candidates("acme.co.in")
    assert lookalike.candidates("ab.com") == []


def test_lookalike_evaluate_skips_defensive():
    reg = {"acmbank.com": {"ns": ["ns1.evil.example"], "mx": ["mx.evil.example"], "a": ["198.51.100.1"]},
           "acmebank.in": {"ns": ["ns1.acmebank.com"], "mx": [], "a": ["203.0.113.1"]},
           "acme-bank.com": {"ns": ["ns.parking.example"], "mx": [], "a": ["192.0.2.1"]},
           "acmeebank.com": {"ns": ["ns.reg.example"], "mx": [], "a": []}}
    fs = lookalike.evaluate("acmebank.com", reg, {"ns1.acmebank.com"})
    assert [(f.code, f.asset_value, f.severity) for f in fs] == [
        ("lookalike_domain_mail", "acmbank.com", "low"), ("lookalike_domain_web", "acme-bank.com", "info")]


def test_lookalike_collect(monkeypatch):
    monkeypatch.setattr(lookalike, "_ns", lambda d: {"ns1.acmebank.com"})
    probe = lambda d: {"ns": ["ns.x.example"], "mx": ["mx.x.example"], "a": []} if d == "acmbank.com" else None
    fs, cov = lookalike.collect("acmebank.com", probe_fn=probe)
    assert codes(fs) == ["lookalike_domain_mail"] and cov == 1
    monkeypatch.setattr(lookalike, "_ns", lambda d: set())
    assert lookalike.collect("acmebank.com", probe_fn=probe) == ([], 0)
