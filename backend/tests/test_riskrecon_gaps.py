from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app import assets, auth, db, main, policy
from app.auth import create_user
from app.collectors import web
from app.models import AssetProfile, Entity, Finding, Score

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    create_user(s, "Client", "member@c.example", PASSWORD)
    create_user(s, "Other", "user@o.example", PASSWORD)
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def test_page_profile_and_governance():
    html = '<form><input name="u"><input type="password" name="p"></form><script src="https://checkout.razorpay.com/v1/x.js"></script>'
    p = web.profile(html, ["SESSIONID=1; Secure"])
    assert p == {"login": True, "payment": True, "forms": True, "session": True}
    assert web.profile("<p>hello</p>", [])["login"] is False
    big = "<html>" + "x" * 6000 + "</html>"
    codes = {f.code for f in web.governance("acme.example", big, False)}
    assert codes == {"security_txt_missing", "privacy_policy_missing"}
    assert web.governance("acme.example", big + '<a href="/privacy-policy">Privacy</a>', True) == []
    assert web.governance("acme.example", "<div id=root></div>", None) == []  # JS-built page: not judged


def test_classify_host():
    assert assets.classify_host("login.acme.example", "acme.example", None, set())[0] == "high"
    assert assets.classify_host("blog.acme.example", "acme.example", {"login": True}, set())[0] == "high"
    assert assets.classify_host("mx1.acme.example", "acme.example", None, {"mx1.acme.example"})[0] == "high"
    assert assets.classify_host("acme.example", "acme.example", None, set())[0] == "medium"
    assert assets.classify_host("api.acme.example", "acme.example", None, set())[0] == "medium"
    assert assets.classify_host("old-promo.acme.example", "acme.example", {"login": False}, set())[0] == "low"
    assert assets.priority("high", "high") == 1 and assets.priority("high", "low") == 3 and assets.priority("low", "low") == 4


def _entity_with_assets():
    s = db.SessionLocal()
    e = s.query(Entity).first()
    for asset, value, country in (("login.v.example", "high", "IN"), ("promo.v.example", "low", "US"), ("1.2.3.4", "medium", "RU")):
        s.add(AssetProfile(entity_id=e.id, asset=asset, kind="ip" if asset[0].isdigit() else "host", value=value,
                           reasons=[], country=country, provider="Some Cloud", asn="64500"))
    s.add(Finding(entity_id=e.id, asset_value="login.v.example", risk_factor="web_security", code="session_cookie_not_httponly",
                  title="t", severity="high", detection_confidence=1.0, evidence={}))
    s.add(Finding(entity_id=e.id, asset_value="promo.v.example", risk_factor="web_security", code="csp_missing",
                  title="t", severity="high", detection_confidence=1.0, evidence={}))
    s.add(Score(entity_id=e.id, overall=650, grade="C", model_version="t", factors={}, trace={}))
    s.commit()
    eid = e.id
    s.close()
    return eid


def test_refresh_profiles_uses_lookup(monkeypatch):
    s = db.SessionLocal()
    e = Entity(name="V", primary_domain="v.example")
    s.add(e)
    s.commit()
    monkeypatch.setattr(assets, "resolve", lambda name, rtype: [])
    assets.refresh(s, e, {"v.example": {"login": True}}, lookup=lambda ip: {"asn": "13335", "country": "US", "provider": "CLOUDFLARENET"},
                   first_ip=lambda h: "104.16.0.1")
    rows = {p.asset: p for p in s.query(AssetProfile).all()}
    assert rows["v.example"].value == "high" and rows["v.example"].provider == "CLOUDFLARENET"
    assert rows["www.v.example"].country == "US"
    s.close()


def test_assets_endpoint():
    user, other = login("member@c.example"), login("user@o.example")
    user.post("/api/entities", json={"name": "V", "primary_domain": "v.example", "tier": 1})
    eid = _entity_with_assets()
    r = user.get(f"/api/entities/{eid}/assets").json()
    assert r["counts"] == {"high": 1, "medium": 1, "low": 1}
    assert r["matrix"]["high"] == {"high": 1, "medium": 0, "low": 1}
    assert r["priorities"]["1"] == 1 and r["priorities"]["3"] == 1
    assert r["hosting"]["outside_home"] == 2 and r["hosting"]["high_risk"] == ["1.2.3.4"]
    assert r["assets"][0]["asset"] == "login.v.example"
    assert other.get(f"/api/entities/{eid}/assets").status_code == 404
    f = {x["asset"]: x for x in user.get(f"/api/entities/{eid}").json()["findings"]}
    assert f["login.v.example"]["priority"] == 1 and f["promo.v.example"]["priority"] == 3


def test_policy_evaluate():
    now = datetime.now(timezone.utc)
    score = SimpleNamespace(overall=650, created_at=now - timedelta(days=20))
    findings = [SimpleNamespace(id=1, code="kev_exposed", severity="critical", asset_value="1.2.3.4", status="open", evidence={"kev": True})]
    profiles = [SimpleNamespace(asset="1.2.3.4", value="high", country="IR")]
    breaches = {b["rule"] for b in policy.evaluate(policy.DEFAULT_RULES["1"], score=score, findings=findings,
                                                    profiles=profiles, certs=[], industry=None, now=now)}
    assert breaches == {"min_score", "max_critical", "max_priority1", "require_certificate", "no_high_risk_hosting",
                        "max_days_since_scan"}
    assert policy.evaluate(policy.DEFAULT_RULES["3"], score=SimpleNamespace(overall=800, created_at=now), findings=[],
                           profiles=[], certs=[], industry=None) == []
    assert policy.evaluate(policy.DEFAULT_RULES["3"], score=None, findings=[], profiles=[], certs=[], industry=None)[0]["rule"] == "unrated"


def test_policy_endpoints():
    admin, member, other = login("admin@c.example"), login("member@c.example"), login("user@o.example")
    admin.post("/api/entities", json={"name": "V", "primary_domain": "v.example", "tier": 1})
    _entity_with_assets()
    p = member.get("/api/policy").json()
    assert p["is_default"] and p["rules"]["1"]["min_score"] == 700
    c = member.get("/api/policy/compliance").json()
    assert c["total"] == 1 and c["compliant"] == 0
    rules = {k: {kk: None for kk in policy.RULE_KEYS} for k in ("1", "2", "3")}
    rules["1"]["min_score"] = 600
    assert member.put("/api/policy", json={"rules": rules}).status_code == 403
    assert admin.put("/api/policy", json={"rules": {**rules, "1": {"min_score": 5000}}}).status_code == 422
    saved = admin.put("/api/policy", json={"rules": rules}).json()
    assert not saved["is_default"] and saved["rules"]["1"]["require_certificate"] is False
    assert member.get("/api/policy/compliance").json()["compliant"] == 1
    assert other.get("/api/policy").json()["is_default"]
    assert other.get("/api/policy/compliance").json()["total"] == 0
