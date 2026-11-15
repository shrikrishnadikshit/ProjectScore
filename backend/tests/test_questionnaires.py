from fastapi.testclient import TestClient

from app import auth, db, main
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Entity
from app.questionnaires import QUESTIONS
from app.scan import scan_entity

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


def test_questionnaire_flow():
    admin, member, other = login("admin@c.example"), login("member@c.example"), login("admin@o.example")
    eid = admin.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    s = db.SessionLocal()
    scan_entity(s, s.get(Entity, eid), lambda e: (
        [RawFinding("email_security", "dmarc_missing", "No DMARC record", "high", "vendor.example")],
        {"email_security": 1}))
    s.close()

    assert member.post(f"/api/entities/{eid}/questionnaires", json={"recipient_email": "sec@vendor.example"}).status_code == 403
    q = admin.post(f"/api/entities/{eid}/questionnaires", json={"recipient_email": "sec@vendor.example"}).json()
    token = q["link_path"].split("/")[-1]

    vendor = TestClient(main.app)
    page = vendor.get(f"/api/public/questionnaire/{token}").json()
    assert page["company"] == "V" and page["requested_by"] == "Client" and len(page["questions"]) == len(QUESTIONS)
    partial = {"mail1": {"answer": "yes", "comment": "We have DMARC"}}
    assert vendor.put(f"/api/public/questionnaire/{token}", json={"answers": partial}).json()["status"] == "in_progress"
    assert vendor.put(f"/api/public/questionnaire/{token}", json={"answers": partial, "submit": True}).status_code == 422
    full = {qid: {"answer": "yes"} for qid, *_ in QUESTIONS}
    full["gov3"] = {"answer": "no"}
    assert vendor.put(f"/api/public/questionnaire/{token}", json={"answers": full, "submit": True}).json()["status"] == "submitted"
    assert vendor.put(f"/api/public/questionnaire/{token}", json={"answers": full}).status_code == 409

    detail = member.get(f"/api/questionnaires/{q['id']}").json()
    assert detail["score"] == round(100 * (len(QUESTIONS) - 1) / len(QUESTIONS))
    assert [c["question"] for c in detail["contradictions"]] == ["mail1"]
    assert other.get(f"/api/questionnaires/{q['id']}").status_code == 404
    assert admin.post(f"/api/questionnaires/{q['id']}/review", json={"note": "Ask about DMARC"}).json()["status"] == "reviewed"
    assert vendor.get("/api/public/questionnaire/bad-token").status_code == 404
