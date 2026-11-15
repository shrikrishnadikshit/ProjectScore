from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app import alerts, attackpaths, auth, db, main, remediation
from app.collectors import darkweb as feeds
from app.models import Finding

PASSWORD = "correct-horse-battery"
NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    from app.auth import create_user
    create_user(s, "Client", "member@c.example", PASSWORD)
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


LEAKS = [
    {"victim": "Acme Corp", "domain": "acme.com", "group": "akira", "discovered": "2026-10-28T10:05:41+00:00", "url": "https://x/1"},
    {"victim": "Acme Widgets", "domain": "acmewidgets.de", "group": "play", "discovered": "2026-10-01T00:00:00+00:00"},
    {"victim": "Other", "domain": "", "group": "lockbit", "discovered": "2026-10-01T00:00:00+00:00", "description": "mentions acme.com"},
    {"victim": "Acme", "domain": "www.acme.com", "group": "old", "discovered": "2024-01-01T00:00:00+00:00"},
]
STEALERS = {"total": 120, "employees": 12, "users": 108, "third_parties": 3, "last_employee_compromised": "2026-11-01T00:00:00.000Z",
            "last_user_compromised": "2026-11-10T00:00:00.000Z", "stealerFamilies": {"total": 120, "RedLine": 70, "Lumma": 40},
            "data": {"employees_urls": [{"occurrence": 5, "type": "Employee", "url": "https://vpn.acme.com/login"},
                                         {"occurrence": 2, "type": "Employee", "url": "https://vpn.acme.com/x"},
                                         {"occurrence": 1, "type": "Employee", "url": "https://dash.acme.com/:bob@mail.com:Secret1"},
                                         {"occurrence": 1, "type": "Employee", "url": "bob@mail.com:pw@acme.com"}]}}


def test_leak_matching():
    f = feeds.evaluate_leaks(LEAKS, "acme.com", "Acme Corp", NOW)
    assert len(f) == 1  # other names, description mentions and old listings ignored
    assert f[0].severity == "critical" and f[0].risk_factor == "compromise" and f[0].evidence["group"] == "akira"


def test_stealers():
    f = {x.code: x for x in feeds.evaluate_stealers(STEALERS, "acme.com", NOW)}
    assert f["infostealer_employees"].severity == "high"
    assert f["infostealer_employees"].evidence["families"] == ["RedLine", "Lumma"]
    assert f["infostealer_customers"].severity == "low"
    logins = f["infostealer_employees"].evidence["employee_logins"]
    assert logins == [{"url": "vpn.acme.com", "count": 7}, {"url": "dash.acme.com", "count": 1}]
    assert "Secret1" not in str(f["infostealer_employees"].evidence) and "bob" not in str(f["infostealer_employees"].evidence)
    old = dict(STEALERS, employees=2, last_employee_compromised="2024-01-01T00:00:00Z")
    assert {x.code: x for x in feeds.evaluate_stealers(old, "acme.com", NOW)}["infostealer_employees"].severity == "low"
    assert feeds.evaluate_stealers({"employees": 0, "users": 0}, "acme.com", NOW) == []


def test_collect_off_by_default():
    assert feeds.collect("acme.com", "Acme") == ([], 0)
    found, checked = feeds.collect("acme.com", "Acme Corp", leak_fn=lambda d: LEAKS, stealer_fn=lambda d: STEALERS)
    codes = {x.code for x in found}
    assert checked == 2 and "infostealer_employees" in codes and any(c.startswith("ransomware_leak_") for c in codes)


def test_guidance_and_paths():
    assert remediation.guidance("ransomware_leak_akira_20261028") is not remediation.DEFAULT
    assert remediation.guidance("infostealer_employees") is not remediation.DEFAULT

    class F:
        def __init__(self, code, severity="high"):
            self.code, self.severity, self.status, self.evidence, self.id, self.title, self.asset_value = code, severity, "open", {}, 1, code, "x"
    p = {x["id"]: x for x in attackpaths.paths([F("ransomware_leak_akira_1"), F("dmarc_missing"), F("infostealer_employees")])}
    assert p["already_compromised"]["steps"][0]["state"] == "evidence"
    assert p["phish_to_ransomware"]["steps"][2]["state"] == "evidence"


def test_darkweb_endpoints_and_alert():
    user, other = login("member@c.example"), login("admin@o.example")
    eid = user.post("/api/entities", json={"name": "Acme Corp", "primary_domain": "acme.com"}).json()["id"]
    s = db.SessionLocal()
    for raw in feeds.evaluate_leaks(LEAKS, "acme.com", "Acme Corp", NOW) + feeds.evaluate_stealers(STEALERS, "acme.com", NOW):
        s.add(Finding(entity_id=eid, asset_value=raw.asset_value, risk_factor=raw.risk_factor, code=raw.code, title=raw.title,
                      severity=raw.severity, detection_confidence=raw.detection_confidence, evidence=raw.evidence))
    s.commit()
    fs = s.query(Finding).filter_by(entity_id=eid).all()
    from app.models import Entity, Score
    ent = s.get(Entity, eid)
    prev = Score(entity_id=eid, overall=800, grade="A", factors={})
    evs = alerts.events(ent, prev, prev, fs)
    assert evs[0]["kind"] == "dark_web" and evs[0]["severity"] == "critical"
    s.close()
    r = user.get(f"/api/entities/{eid}/darkweb").json()
    assert r["level"] == "critical" and r["leak_sites"][0]["group"] == "akira"
    assert r["infostealers"]["employees"] == 12 and r["infostealers"]["users"] == 108
    assert other.get(f"/api/entities/{eid}/darkweb").status_code == 404
    p = user.get("/api/darkweb").json()
    assert p["companies"][0]["name"] == "Acme Corp" and other.get("/api/darkweb").json()["companies"] == []
