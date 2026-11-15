
from fastapi.testclient import TestClient

from app import attackpaths, auth, db, main
from app.auth import create_user
from app.models import Finding

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Platform", "owner@p.example", PASSWORD, role="owner")
    create_user(s, "Client", "member@c.example", PASSWORD)
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


class F:
    def __init__(self, code, evidence=None, id=1):
        self.code, self.evidence, self.status, self.asset_value, self.id = code, evidence or {}, "open", "x", id
        self.title, self.severity = code, "high"


def test_attack_paths():
    none = attackpaths.paths([])
    assert none == []
    p = {x["id"]: x for x in attackpaths.paths([
        F("dmarc_missing"), F("lookalike_domain_mail"), F("breach_x", {"data_classes": ["Passwords"]}),
        F("rdp_exposed_3389"), F("csp_missing")])}
    assert p["phish_to_ransomware"]["status"] == "open"
    assert p["remote_access"]["status"] == "open"
    assert p["web_session_theft"]["status"] == "entry_point"  # no session-cookie weakness seen
    assert "exploit_public_app" not in p
    steps = p["phish_to_ransomware"]["steps"]
    assert steps[1]["technique"]["id"] == "T1566" and steps[-1]["state"] == "assumed"


def test_attack_paths_endpoint():
    user, other = login("member@c.example"), login("admin@o.example")
    eid = user.post("/api/entities", json={"name": "V", "primary_domain": "v.example"}).json()["id"]
    s = db.SessionLocal()
    s.add(Finding(entity_id=eid, asset_value="1.2.3.4", risk_factor="vulnerability", code="kev_exposed", title="KEV",
                  severity="critical", detection_confidence=1.0, evidence={"kev": True, "cves": ["CVE-1"]}))
    s.commit()
    s.close()
    r = user.get(f"/api/entities/{eid}/attack-paths").json()
    assert r[0]["id"] == "exploit_public_app" and r[0]["status"] == "open"
    assert other.get(f"/api/entities/{eid}/attack-paths").status_code == 404

