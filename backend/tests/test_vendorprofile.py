from datetime import date, timedelta

from fastapi.testclient import TestClient

from app import auth, db, main, vendorprofile
from app.auth import create_user
from app.models import Alert

PASSWORD = "correct-horse-battery"


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


def test_profile_and_offboarding():
    admin, member, other = login("admin@c.example"), login("member@c.example"), login("admin@o.example")
    eid = admin.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    end = (date.today() + timedelta(days=30)).isoformat()
    p = member.put(f"/api/entities/{eid}/profile", json={"details": {"services": "Payroll", "data_types": ["personal", "financial"],
                                                                      "business_owner": "HR", "contract_end": end, "country": "IN"}}).json()
    assert p["details"]["services"] == "Payroll" and p["details"]["contract_end"] == end
    assert member.put(f"/api/entities/{eid}/profile", json={"details": {"contract_end": "soon"}}).status_code == 422
    assert other.get(f"/api/entities/{eid}/profile").status_code == 404
    s = db.SessionLocal()
    assert vendorprofile.contract_reminders(s) == 1 and vendorprofile.contract_reminders(s) == 0
    assert s.query(Alert).filter_by(kind="contract_ending").count() == 1
    s.close()
    assert member.patch(f"/api/entities/{eid}/offboarding", json={"key": "access", "done": True}).status_code == 409
    assert member.post(f"/api/entities/{eid}/offboarding").status_code == 403
    admin.post(f"/api/entities/{eid}/offboarding")
    for k, _ in vendorprofile.CHECKLIST:
        r = member.patch(f"/api/entities/{eid}/offboarding", json={"key": k, "done": True}).json()
    assert r["offboarding"]["completed_at"] and all(i["done"] for i in r["offboarding"]["items"])
    r = member.patch(f"/api/entities/{eid}/offboarding", json={"key": "data", "done": False}).json()
    assert r["offboarding"]["completed_at"] is None
