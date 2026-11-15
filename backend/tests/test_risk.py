from fastapi.testclient import TestClient

from app import auth, db, main, risk
from app.auth import create_user
from app.models import Entity
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "user@c.example", PASSWORD)
    create_user(s, "Other", "user@o.example", PASSWORD)
    s.close()


def test_estimate_shape():
    good, bad = risk.estimate(850, None), risk.estimate(450, None)
    assert bad["probability"] > good["probability"] and abs(risk.probability(700) - risk.BASE_PROBABILITY) < 1e-9
    big = risk.estimate(700, 100000, "high")
    assert big["impact_crore"] > risk.estimate(700, 100, "low")["impact_crore"]
    assert big["range_crore"][0] < big["expected_loss_crore"] < big["range_crore"][1]


def test_risk_inputs_are_per_organisation():
    c, o = TestClient(main.app), TestClient(main.app)
    c.post("/api/auth/login", json={"email": "user@c.example", "password": PASSWORD})
    o.post("/api/auth/login", json={"email": "user@o.example", "password": PASSWORD})
    eid = c.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    o.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"})
    s = db.SessionLocal()
    scan_entity(s, s.get(Entity, eid), lambda e: ([], {"tls": 1}))
    s.close()
    assert c.get(f"/api/entities/{eid}/risk").json()["expected_loss_crore"] > 0
    assert c.put(f"/api/entities/{eid}/risk", json={"revenue_crore": -5}).status_code == 422
    r = c.put(f"/api/entities/{eid}/risk", json={"revenue_crore": 5000, "sensitivity": "high"}).json()
    assert r["revenue_crore"] == 5000 and r["sensitivity"] == "high"
    assert o.get(f"/api/entities/{eid}/risk").json()["revenue_crore"] is None
