from fastapi.testclient import TestClient

from app import auth, brandprotect as bp, db, main, remediation
from app.auth import create_user
from app.collectors import RawFinding, impersonation
from app.models import Entity, Finding

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "member@c.example", PASSWORD)
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def page(html, host="x", status=200):
    import re
    m = re.search(r"<title>(.*?)</title>", html)
    return {"status": status, "final_host": host, "html": html, "title": m.group(1) if m else ""}


PAGES = {
    "acme.com": page("<title>Acme Bank | Online Banking</title>", "acme.com"),
    "acme-login.com": page("<title>Acme Bank | Online Banking</title><form><input type='password'></form>", "acme-login.com"),
    "acmee.com": page("<title>Acme Bank Online Banking</title>", "acmee.com"),
    "acrne.com": page("<title>Welcome</title><p>This domain is for sale</p>", "acrne.com"),
    "acme.net": page("", "www.acme.com"),
    "acme.org": page("<title>Gardening tips</title>", "acme.org"),
}


def test_impersonation_check():
    look = [RawFinding("brand", "lookalike_domain_web", "t", "info", d, {}) for d in PAGES if d != "acme.com"]
    out = {f.asset_value: f for f in impersonation.check("acme.com", "Acme Bank Ltd", look, fetch_fn=PAGES.get)}
    assert out["acme-login.com"].code == "impersonation_phishing_like" and out["acme-login.com"].severity == "high"
    assert out["acmee.com"].code == "impersonation_copies_site"
    assert out["acme.net"].code == "impersonation_redirects_to_real" and out["acme.net"].severity == "info"
    assert "acrne.com" not in out and "acme.org" not in out
    assert remediation.guidance("impersonation_phishing_like") is not remediation.DEFAULT


def test_apps_news_social():
    apps = bp.classify_apps([
        {"trackName": "Acme Mobile Banking", "sellerName": "Acme Bank Limited", "sellerUrl": "https://www.acme.com/app", "trackViewUrl": "u1"},
        {"trackName": "Acme Bank Login Helper", "sellerName": "Fast Apps LLC", "trackViewUrl": "u2"},
        {"trackName": "Recipe Box", "sellerName": "Cook Co"},
    ], "Acme Bank Ltd", "acme.com")
    assert [(a["name"], a["official"]) for a in apps] == [("Acme Bank Login Helper", False), ("Acme Mobile Banking", True)]
    news = bp.classify_news([
        {"title": "Acme Bank hit by ransomware attack", "url": "n1", "domain": "news.example", "seendate": "20261101T101500Z"},
        {"title": "Acme Bank hit by ransomware attack", "url": "n1b", "domain": "copy.example", "seendate": "20261101T111500Z"},
        {"title": "Acme Bank opens new branch", "url": "n2", "seendate": "20261101T101500Z"},
        {"title": "Other firm hacked", "url": "n3", "seendate": "20261101T101500Z"},
    ], "Acme Bank", "acme.com")
    assert [(n["url"], n["date"]) for n in news] == [("n1", "2026-11-01")]
    social = bp.social_links('<a href="https://twitter.com/share?x">s</a><a href="https://x.com/acmebank">x</a>'
                             '<a href="https://www.linkedin.com/company/acme-bank/">li</a><a href="https://facebook.com/sharer/x">f</a>')
    assert social == [{"platform": "LinkedIn", "url": "https://www.linkedin.com/company/acme-bank"},
                      {"platform": "X (Twitter)", "url": "https://x.com/acmebank"}]


def test_brand_endpoint():
    user, other = login("member@c.example"), login("admin@o.example")
    eid = user.post("/api/entities", json={"name": "Acme Bank", "primary_domain": "acme.com"}).json()["id"]
    s = db.SessionLocal()
    s.add(Finding(entity_id=eid, asset_value="acme-login.com", risk_factor="brand", code="impersonation_phishing_like",
                  title="Possible phishing site", severity="high", detection_confidence=0.7, evidence={"kind": "phishing_like"}))
    bp.refresh(s, s.get(Entity, eid),
               apps_fn=lambda n, d, c: [{"trackName": "Acme Wallet", "sellerName": "Someone Else"}],
               news_fn=lambda n, d: [{"title": "Acme Bank data breach exposes customers", "url": "n", "seendate": "20261101T000000Z"}],
               social_fn=lambda d: [{"platform": "LinkedIn", "url": "https://www.linkedin.com/company/acme"}])
    s.close()
    r = user.get(f"/api/entities/{eid}/brand").json()
    assert r["level"] == "high" and r["fake_sites"][0]["domain"] == "acme-login.com"
    assert r["unofficial_apps"] == 1 and len(r["news"]) == 1 and r["social"][0]["platform"] == "LinkedIn"
    assert "website" in r["report"]
    assert other.get(f"/api/entities/{eid}/brand").status_code == 404
