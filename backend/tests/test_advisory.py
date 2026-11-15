from fastapi.testclient import TestClient

from app import auth, db, main
from app.auth import create_user

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Platform", "owner@p.example", PASSWORD, role="owner")
    create_user(s, "Client", "user@c.example", PASSWORD)
    create_user(s, "Other", "user@o.example", PASSWORD)
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def test_advisory_flow():
    owner, user, other = login("owner@p.example"), login("user@c.example"), login("user@o.example")
    eid = user.post("/api/entities", json={"name": "V", "primary_domain": "v.example"}).json()["id"]
    assert user.post(f"/api/entities/{eid}/advisory", json={"service": "nope"}).status_code == 422
    assert other.post(f"/api/entities/{eid}/advisory", json={"service": "fix_guidance"}).status_code == 404
    r = user.post(f"/api/entities/{eid}/advisory", json={"service": "remediation_support",
                                                         "finding_codes": ["dmarc_missing"], "message": "Help with DMARC"}).json()
    assert r["status"] == "new" and r["entity"]["name"] == "V"
    assert other.get("/api/advisory").json() == []
    assert owner.get("/api/advisory").json()[0]["organisation"] == "Client"
    assert user.post(f"/api/advisory/{r['id']}", json={"status": "done"}).status_code == 403
    owner.post(f"/api/advisory/{r['id']}", json={"status": "in_progress", "owner_note": "Call booked for Monday"})
    mine = user.get("/api/advisory").json()[0]
    assert mine["status"] == "in_progress" and mine["owner_note"] == "Call booked for Monday"
