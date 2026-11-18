from datetime import date, timedelta

from fastapi.testclient import TestClient

from app import auth, db, main, workflow
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Alert, Entity, RemediationTask
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"
DMARC = RawFinding("email_security", "dmarc_missing", "No DMARC record", "high", "vendor.example")
TLS = RawFinding("tls", "tls_expired", "Certificate expired", "critical", "vendor.example")


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    create_user(s, "Client", "member@c.example", PASSWORD)
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def scan(eid, findings, factors):
    s = db.SessionLocal()
    scan_entity(s, s.get(Entity, eid), lambda e: (findings, factors))
    s.close()


def test_tasks_verify_and_mttr():
    admin, member, other = login("admin@c.example"), login("member@c.example"), login("admin@o.example")
    eid = admin.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    scan(eid, [DMARC, TLS], {"email_security": 1, "tls": 1})
    me = member.get("/api/auth/me").json()
    t = member.post("/api/tasks", json={"entity_id": eid, "code": "tls_expired", "assignee_id": me["id"]}).json()
    assert t["severity"] == "critical" and t["due"] == (date.today() + timedelta(days=7)).isoformat()
    assert member.post("/api/tasks", json={"entity_id": eid, "code": "tls_expired"}).status_code == 409
    assert member.post("/api/tasks", json={"entity_id": eid, "code": "nothing"}).status_code == 404
    assert other.post("/api/tasks", json={"entity_id": eid, "code": "tls_expired"}).status_code == 404
    t2 = admin.post("/api/tasks", json={"entity_id": eid, "code": "dmarc_missing", "assignee_email": "it@vendor.example"}).json()
    assert member.patch(f"/api/tasks/{t2['id']}", json={"status": "fixed"}).json()["status"] == "fixed"
    assert member.patch(f"/api/tasks/{t['id']}", json={"status": "wont_fix"}).status_code == 403
    assert member.patch(f"/api/tasks/{t['id']}", json={"status": "verified"}).status_code == 422
    assert other.patch(f"/api/tasks/{t['id']}", json={"status": "fixed"}).status_code == 404
    # rescan: TLS fixed, DMARC still there
    scan(eid, [DMARC], {"email_security": 1, "tls": 1})
    tasks = {x["code"]: x for x in admin.get("/api/tasks?open_only=false").json()["tasks"]}
    assert tasks["tls_expired"]["status"] == "verified" and tasks["tls_expired"]["closed_at"]
    assert tasks["dmarc_missing"]["status"] == "in_progress"
    assert "still sees" in tasks["dmarc_missing"]["history"][-1]["action"]
    st = admin.get("/api/tasks").json()["stats"]
    assert st["verified"] == 1 and st["open"] == 1 and st["mttr_days"] is not None and st["on_time_pct"] == 100

    s = db.SessionLocal()
    row = s.get(RemediationTask, t2["id"])
    row.due = date.today() - timedelta(days=1)
    s.commit()
    assert workflow.overdue_alerts(s) == 1 and workflow.overdue_alerts(s) == 0
    assert s.query(Alert).filter_by(kind="task_overdue").count() == 1
    s.close()


def test_risk_acceptance_and_prefs():
    admin, member = login("admin@c.example"), login("member@c.example")
    eid = admin.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    scan(eid, [DMARC], {"email_security": 1})
    t = member.post("/api/tasks", json={"entity_id": eid, "code": "dmarc_missing"}).json()
    soon = (date.today() + timedelta(days=30)).isoformat()
    assert member.post("/api/acceptances", json={"entity_id": eid, "reason": "short", "expires_on": soon}).status_code == 422
    assert member.post("/api/acceptances", json={"entity_id": eid, "reason": "Mail sent only via a gateway we control",
                                                  "expires_on": (date.today() + timedelta(days=400)).isoformat()}).status_code == 422
    a = member.post("/api/acceptances", json={"entity_id": eid, "code": "dmarc_missing", "expires_on": soon,
                                              "reason": "Mail sent only via a gateway we control", "controls": "Gateway DKIM"}).json()
    assert a["status"] == "pending"
    assert member.post(f"/api/acceptances/{a['id']}/decide", json={"approve": True}).status_code == 403
    a = admin.post(f"/api/acceptances/{a['id']}/decide", json={"approve": True}).json()
    assert a["status"] == "approved" and a["approver"] and not a["self_approved"]
    assert admin.get("/api/tasks?open_only=false").json()["tasks"][0]["status"] == "accepted"
    s = db.SessionLocal()
    assert workflow.expire_acceptances(s, date.today() + timedelta(days=31)) == 1
    s.close()
    assert admin.get("/api/tasks").json()["tasks"][0]["status"] == "open"
    assert admin.get("/api/acceptances").json()[0]["status"] == "expired"

    assert member.put("/api/org/preferences", json={"score_drop": 50}).status_code == 403
    p = admin.put("/api/org/preferences", json={"score_drop": 50, "sla_days": {"high": 14}, "rescan_days": 3}).json()
    assert p["score_drop"] == 50 and p["sla_days"]["high"] == 14 and p["sla_days"]["critical"] == 7
    assert admin.put("/api/org/preferences", json={"rescan_days": 2}).status_code == 422
    t3 = member.patch(f"/api/tasks/{t['id']}", json={"due": "2030-01-01"}).json()
    assert t3["due"] == "2030-01-01"


def test_residual_risk():
    r = workflow.residual(80, 850, 90, 0, 0)
    assert r["score"] < 40 and r["level"] in ("low", "medium")
    bad = workflow.residual(80, 450, 20, 2, 3)
    assert bad["score"] > r["score"] and bad["level"] in ("high", "critical")
    assert workflow.residual(None, 800, None, 0, 0) is None
