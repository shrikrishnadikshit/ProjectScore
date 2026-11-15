from fastapi.testclient import TestClient

from app import auth, db, main
from app.auth import create_user
from app.collectors import RawFinding
from app.frameworks import FACTOR_CONTROLS, FRAMEWORKS
from app.models import Entity
from app.scan import scan_entity
from app.scoring import FACTOR_WEIGHTS

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "user@c.example", PASSWORD)
    create_user(s, "Other", "user@o.example", PASSWORD)
    s.close()


def test_mapping_references_are_consistent():
    for factor, fws in FACTOR_CONTROLS.items():
        assert factor in FACTOR_WEIGHTS
        for fw, ids in fws.items():
            assert all(i in FRAMEWORKS[fw]["controls"] for i in ids), (factor, fw)


def test_entity_frameworks():
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": "user@c.example", "password": PASSWORD})
    eid = c.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    s = db.SessionLocal()
    raw = [RawFinding("tls", "cert_expired", "Certificate has expired", "high", "www.vendor.example")]
    scan_entity(s, s.get(Entity, eid), lambda e: (raw, {"tls": 1, "email_security": 1}))
    s.close()
    fws = {f["key"]: {c["id"]: c for c in f["controls"]} for f in c.get(f"/api/entities/{eid}/frameworks").json()}
    assert fws["iso27001"]["A.8.24"]["status"] == "issues"
    assert fws["iso27001"]["A.8.24"]["findings"][0]["title"] == "Certificate has expired"
    assert fws["iso27001"]["A.5.14"]["status"] == "no_issues"
    assert fws["iso27001"]["A.8.8"]["status"] == "not_assessed"
    assert fws["cert_in"]["Logs and time sync"]["status"] == "out_of_scope"

    other = TestClient(main.app)
    other.post("/api/auth/login", json={"email": "user@o.example", "password": PASSWORD})
    assert other.get(f"/api/entities/{eid}/frameworks").status_code == 404
