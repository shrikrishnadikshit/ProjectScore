from fastapi.testclient import TestClient

from app import auth, db, main
from app.auth import create_user
from app.models import Entity
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Platform", "owner@p.example", PASSWORD, role="owner")
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    s.close()


def test_incident_and_backtest():
    owner, admin = TestClient(main.app), TestClient(main.app)
    owner.post("/api/auth/login", json={"email": "owner@p.example", "password": PASSWORD})
    admin.post("/api/auth/login", json={"email": "admin@c.example", "password": PASSWORD})
    s = db.SessionLocal()
    e = Entity(name="V", primary_domain="v.example")
    s.add(e)
    s.commit()
    scan_entity(s, e, lambda x: ([], {"tls": 1}))
    eid = e.id
    s.close()
    body = {"occurred_on": "2099-01-01", "kind": "ransomware", "description": "Ransomware reported in news"}
    assert admin.post(f"/api/entities/{eid}/incidents", json=body).status_code == 403
    r = owner.post(f"/api/entities/{eid}/incidents", json=body).json()
    assert r["score_before"] == 900
    assert owner.post(f"/api/entities/{eid}/incidents", json={**body, "kind": "x"}).status_code == 422
    bt = owner.get("/api/backtest").json()
    assert bt["incidents"] == 1 and bt["mean_score_before_incident"] == 900
