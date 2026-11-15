import pytest
from fastapi.testclient import TestClient

from app import auth, db, main, optout
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Entity
from app.scan import OptedOut, scan_entity

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    optout.limiter.hits.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Platform", "owner@p.example", PASSWORD, role="owner")
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    assert c.post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200
    return c


def test_public_request_review_and_scan_exclusion():
    public = TestClient(main.app)
    r = public.post("/api/public/opt-out", json={"domain": "https://www.Acme.example/path",
                                                 "contact_email": "it@acme.example", "reason": "Please stop"})
    assert r.status_code == 202
    assert public.post("/api/public/opt-out", json={"domain": "bad", "contact_email": "x@y.example"}).status_code == 422
    assert public.get("/api/opt-outs").status_code == 401
    assert login("admin@c.example").get("/api/opt-outs").status_code == 403

    owner = login("owner@p.example")
    req = owner.get("/api/opt-outs").json()[0]
    assert req["domain"] == "acme.example" and req["status"] == "pending"

    client = login("admin@c.example")
    eid = client.post("/api/entities", json={"name": "Acme", "primary_domain": "shop.acme.example"}).json()["id"]
    assert client.get(f"/api/entities/{eid}").json()["opted_out"] is False

    assert owner.post(f"/api/opt-outs/{req['id']}", json={"status": "approved"}).json()["status"] == "approved"
    assert client.get(f"/api/entities/{eid}").json()["opted_out"] is True
    assert client.post(f"/api/entities/{eid}/scan").status_code == 409
    s = db.SessionLocal()
    with pytest.raises(OptedOut):
        scan_entity(s, s.get(Entity, eid), lambda e: ([RawFinding("tls", "x", "x", "low", "x")], {"tls": 1}))
    s.close()


def test_honeypot_and_rate_limit():
    public = TestClient(main.app)
    body = {"domain": "a.example", "contact_email": "a@a.example"}
    assert public.post("/api/public/opt-out", json={**body, "website": "spam"}).status_code == 202
    for _ in range(5):
        assert public.post("/api/public/opt-out", json=body).status_code == 202
    assert public.post("/api/public/opt-out", json=body).status_code == 429
    owner = login("owner@p.example")
    assert len(owner.get("/api/opt-outs").json()) == 5
