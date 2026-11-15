from fastapi.testclient import TestClient

from app import alerts, auth, db, main
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Entity
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"
COVER = {"email_security": 1, "tls": 1, "web_security": 1}


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "user@c.example", PASSWORD)
    create_user(s, "Other", "user@o.example", PASSWORD)
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def test_alerts_on_drop_and_new_serious(monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "send_email", lambda to, eid, evs: sent.append((to, evs)))
    monkeypatch.setenv("RESEND_API_KEY", "test")
    monkeypatch.setenv("ALERT_EMAIL_FROM", "alerts@p.example")
    monkeypatch.setattr(alerts.threading, "Thread", lambda target, args, daemon: type(
        "T", (), {"start": lambda self: target(*args)})())

    c, other = login("user@c.example"), login("user@o.example")
    eid = c.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    s = db.SessionLocal()
    scan_entity(s, s.get(Entity, eid), lambda e: ([], COVER))
    assert c.get("/api/alerts").json() == []  # nothing on the first scan

    raw = [RawFinding("tls", "cert_expired", "Certificate has expired", "high", "www.vendor.example"),
           RawFinding("email_security", "dmarc_missing", "No DMARC record", "high", "vendor.example")]
    scan_entity(s, s.get(Entity, eid), lambda e: (raw, COVER))
    rows = c.get("/api/alerts").json()
    assert {r["kind"] for r in rows} == {"score_drop", "new_serious"}
    assert "Certificate has expired" in next(r for r in rows if r["kind"] == "new_serious")["detail"]
    assert c.get("/api/alerts/unread-count").json() == {"count": 2}
    assert other.get("/api/alerts").json() == []  # other organisation does not have this company
    assert sent and sent[0][0] == ["user@c.example"]

    # The same findings on the next scan raise nothing new.
    scan_entity(s, s.get(Entity, eid), lambda e: (raw, COVER))
    assert len(c.get("/api/alerts").json()) == 2
    s.close()

    assert other.post(f"/api/alerts/{rows[0]['id']}/read").status_code == 404
    assert c.post(f"/api/alerts/{rows[0]['id']}/read").json()["read"] is True
    c.post("/api/alerts/read-all")
    assert c.get("/api/alerts/unread-count").json() == {"count": 0}


def test_no_email_without_config(monkeypatch):
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    called = []
    monkeypatch.setattr(alerts, "send_email", lambda *a: called.append(a))
    c = login("user@c.example")
    eid = c.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    s = db.SessionLocal()
    scan_entity(s, s.get(Entity, eid), lambda e: ([], COVER))
    scan_entity(s, s.get(Entity, eid), lambda e: (
        [RawFinding("tls", "cert_expired", "Certificate has expired", "critical", "www.vendor.example")], COVER))
    s.close()
    assert c.get("/api/alerts/unread-count").json()["count"] >= 1 and called == []
