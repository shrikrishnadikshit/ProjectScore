from datetime import date, datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app import auth, db, main, optout, privacy
from app.auth import create_user
from app.models import Alert, FreeReport, Organization, PrivacyRequest, RemediationTask, Suppression, VendorProfile

PASSWORD = "correct-horse-battery"
EMAIL = "Jane.Doe@vendor.example"


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
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def test_rights_request_erase_and_suppress():
    public = TestClient(main.app)
    assert public.post("/api/public/privacy-request", json={"kind": "sell", "email": EMAIL}).status_code == 422
    r = public.post("/api/public/privacy-request", json={"kind": "delete", "email": EMAIL, "details": "Please delete me"})
    assert r.status_code == 202 and r.json()["answer_within_days"] == 30

    admin, owner = login("admin@c.example"), login("owner@p.example")
    eid = admin.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    admin.put(f"/api/entities/{eid}/profile", json={"details": {"contact_name": "Jane", "contact_email": EMAIL}})
    s = db.SessionLocal()
    org = s.query(Organization).filter_by(name="Client").first()
    s.add(FreeReport(token="t1", domain="vendor.example", contact_email=EMAIL.lower()))
    s.add(RemediationTask(org_id=org.id, entity_id=eid, code="x", title="x", severity="high", assignee_email=EMAIL,
                          due=date.today(), status="open", history=[]))
    s.commit()
    s.close()

    assert admin.get("/api/privacy-requests").status_code == 403
    req = owner.get("/api/privacy-requests").json()["requests"][0]
    assert req["kind"] == "delete" and req["status"] == "new" and req["due"] == (date.today() + timedelta(days=30)).isoformat()
    found = owner.get(f"/api/privacy-requests/{req['id']}/lookup").json()
    assert found["free_reports"] == 1 and found["fix_owner"] == 1 and found["vendor_contact"] == 1 and not found["suppressed"]

    assert owner.post(f"/api/privacy-requests/{req['id']}", json={"status": "rejected"}).status_code == 422
    done = owner.post(f"/api/privacy-requests/{req['id']}", json={"status": "done", "erase": True, "suppress": True,
                                                                  "note": "Erased"}).json()
    assert done["status"] == "done" and done["result"]["erased"]["free_reports"] == 1 and done["result"]["suppressed"]
    after = owner.get(f"/api/privacy-requests/{req['id']}/lookup").json()
    assert after["free_reports"] == 0 and after["fix_owner"] == 0 and after["vendor_contact"] == 0 and after["suppressed"]
    assert admin.get(f"/api/entities/{eid}/profile").json()["details"]["contact_email"] is None

    s = db.SessionLocal()
    row = s.query(Suppression).one()
    assert "@" not in row.email_hash and len(row.email_hash) == 64  # only a hash is kept
    s.close()
    assert privacy.allowed_recipients(["jane.doe@vendor.example", "ok@vendor.example"]) == ["ok@vendor.example"]
    r = public.post("/api/public/free-report", json={"domain": "vendor.example", "contact_email": EMAIL})
    assert r.status_code == 409


def test_retention():
    s = db.SessionLocal()
    org = s.query(Organization).first()
    old = datetime.now(timezone.utc) - timedelta(days=800)
    s.add_all([FreeReport(token="old", domain="a.example", contact_email="a@a.example", created_at=old),
               FreeReport(token="new", domain="a.example", contact_email="b@a.example"),
               Alert(org_id=org.id, kind="x", severity="info", title="old", created_at=old),
               Alert(org_id=org.id, kind="x", severity="info", title="new"),
               PrivacyRequest(kind="access", email="c@a.example", due=date.today(), status="done",
                              closed_at=datetime.now(timezone.utc) - timedelta(days=1200))])
    s.commit()
    out = privacy.apply_retention(s)
    assert out["free_report_leads"] == 1 and out["alerts"] == 1 and out["closed_privacy_requests"] == 1
    assert [r.token for r in s.query(FreeReport).all()] == ["new"]
    s.close()
    assert TestClient(main.app).get("/api/public/privacy").json()["retention_days"]["alerts"] == 730
