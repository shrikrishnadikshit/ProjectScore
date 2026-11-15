from fastapi.testclient import TestClient
from sqlalchemy import select

from app import auth, db, main, optout
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Entity, Finding
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"
COVER = {"email_security": 1, "tls": 1}


def setup_function():
    auth.throttle._failures.clear()
    optout.limiter.hits.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Platform", "owner@p.example", PASSWORD, role="owner")
    create_user(s, "Client", "user@c.example", PASSWORD)
    create_user(s, "Other", "user@o.example", PASSWORD)
    s.close()


def login(email):
    c = TestClient(main.app)
    assert c.post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200
    return c


def test_dispute_accept_rescores_and_suppresses():
    client, owner, other = login("user@c.example"), login("owner@p.example"), login("user@o.example")
    eid = client.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    s = db.SessionLocal()
    raw = [RawFinding("email_security", "dmarc_missing", "No DMARC", "high", "vendor.example")]
    scan_entity(s, s.get(Entity, eid), lambda e: (raw, COVER))
    before = client.get(f"/api/entities/{eid}").json()
    fid = before["findings"][0]["id"]

    assert client.post(f"/api/findings/{fid}/disputes", json={"reason": "short"}).status_code == 422
    assert other.post(f"/api/findings/{fid}/disputes", json={"reason": "We do have DMARC, see record"}).status_code == 404
    r = client.post(f"/api/findings/{fid}/disputes", json={"reason": "We do have DMARC, see _dmarc record"})
    assert r.status_code == 201
    assert client.post(f"/api/findings/{fid}/disputes", json={"reason": "again again again"}).status_code == 409
    assert client.get("/api/disputes").status_code == 403
    assert client.get(f"/api/entities/{eid}/disputes").json()[0]["status"] == "pending"

    d = owner.get("/api/disputes").json()[0]
    assert d["finding"]["code"] == "dmarc_missing" and d["organisation"] == "Client"
    assert owner.post(f"/api/disputes/{d['id']}", json={"status": "accepted", "note": "Confirmed"}).status_code == 200

    after = client.get(f"/api/entities/{eid}").json()
    assert after["findings"] == [] and after["score"] == 900 > before["score"]

    # The same finding does not come back on the next scan.
    scan_entity(s, s.get(Entity, eid), lambda e: (raw, COVER))
    assert client.get(f"/api/entities/{eid}").json()["findings"] == []
    assert s.scalars(select(Finding).where(Finding.entity_id == eid)).one().status == "false_positive"
    s.close()


def test_reject_keeps_finding_and_public_dispute():
    client, owner = login("user@c.example"), login("owner@p.example")
    eid = client.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    s = db.SessionLocal()
    scan_entity(s, s.get(Entity, eid), lambda e: ([RawFinding("tls", "cert_expired", "Expired", "high", "vendor.example")], COVER))
    s.close()
    fid = client.get(f"/api/entities/{eid}").json()["findings"][0]["id"]
    did = client.post(f"/api/findings/{fid}/disputes", json={"reason": "We renewed the certificate"}).json()["id"]
    owner.post(f"/api/disputes/{did}", json={"status": "rejected", "note": "Still expired on rescan"})
    assert len(client.get(f"/api/entities/{eid}").json()["findings"]) == 1

    public = TestClient(main.app)
    body = {"domain": "vendor.example", "contact_email": "it@vendor.example", "reason": "Your rating of us is wrong"}
    assert public.post("/api/public/disputes", json=body).status_code == 202
    assert public.post("/api/public/disputes", json={**body, "reason": ""}).status_code == 422
    pub = [d for d in owner.get("/api/disputes").json() if d["organisation"] == "Public form"][0]
    assert pub["entity"]["id"] == eid and pub["submitted_by"] == "it@vendor.example"
