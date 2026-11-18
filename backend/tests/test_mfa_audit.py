import time

from fastapi.testclient import TestClient

from app import auth, db, main, mfa
from app.auth import create_user
from app.models import AuditEvent

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
    r = c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c, r.json()


def test_totp_rfc6238_vector():
    # RFC 6238 test secret "12345678901234567890" (SHA-1), T=59 -> 94287082 (8 digits) -> last 6 = 287082
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert mfa.code_at(secret, 59 // 30) == "287082"
    assert mfa.check_code(secret, "287 082", now=59) == 1
    assert mfa.check_code(secret, "287082", last_step=1, now=59) is None  # no reuse
    assert mfa.check_code(secret, "000000", now=59) is None


def test_mfa_flow_and_org_policy():
    admin, _ = login("admin@c.example")
    member, _ = login("member@c.example")
    assert admin.put("/api/org/security", json={"require_mfa": True}).status_code == 409  # own MFA first
    setup = admin.post("/api/auth/mfa/setup").json()
    assert setup["uri"].startswith("otpauth://totp/ProjectScore:admin%40c.example?secret=")
    assert admin.post("/api/auth/mfa/enable", json={"code": "000000"}).status_code == 422
    code = mfa.code_at(setup["secret"], int(time.time() // 30))
    codes = admin.post("/api/auth/mfa/enable", json={"code": code}).json()["recovery_codes"]
    assert len(codes) == 10

    # password alone no longer signs in
    fresh = TestClient(main.app)
    r = fresh.post("/api/auth/login", json={"email": "admin@c.example", "password": PASSWORD}).json()
    assert r["mfa_required"] and fresh.get("/api/auth/me").status_code == 401
    assert fresh.post("/api/auth/mfa", json={"challenge": r["challenge"], "code": "123456"}).status_code == 401
    assert fresh.post("/api/auth/mfa", json={"challenge": r["challenge"] + "x", "code": codes[0]}).status_code == 401
    assert fresh.post("/api/auth/mfa", json={"challenge": r["challenge"], "code": codes[0]}).status_code == 200
    me = fresh.get("/api/auth/me").json()
    assert me["mfa_enabled"] is True
    fresh2 = TestClient(main.app)
    r = fresh2.post("/api/auth/login", json={"email": "admin@c.example", "password": PASSWORD}).json()
    assert fresh2.post("/api/auth/mfa", json={"challenge": r["challenge"], "code": codes[0]}).status_code == 401  # used

    # org requires MFA: the member is blocked until set up, but can reach the setup endpoints
    assert admin.put("/api/org/security", json={"require_mfa": True}).json()["require_mfa"] is True
    assert member.get("/api/entities").json()["detail"] == "mfa_setup_required"
    assert member.get("/api/auth/me").json()["mfa_required"] is True
    s2 = member.post("/api/auth/mfa/setup").json()
    member.post("/api/auth/mfa/enable", json={"code": mfa.code_at(s2["secret"], int(time.time() // 30))})
    assert member.get("/api/entities").status_code == 200
    assert member.post("/api/auth/mfa/disable", json={"password": PASSWORD, "code": "x"}).status_code == 409
    other, _ = login("admin@o.example")
    assert other.get("/api/entities").status_code == 200  # other organisation unaffected


def test_audit_log_chain_and_scope():
    admin, _ = login("admin@c.example")
    admin.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"})
    TestClient(main.app).post("/api/auth/login", json={"email": "admin@c.example", "password": "wrong-password-x"})
    member, _ = login("member@c.example")
    assert member.get("/api/audit").status_code == 403
    ev = admin.get("/api/audit").json()["events"]
    actions = [e["action"] for e in ev]
    assert "POST entities" in actions and "sign_in" in actions
    assert all("wrong-password" not in str(e) for e in ev)
    other, _ = login("admin@o.example")
    assert all(e["actor"] != "admin@c.example" for e in other.get("/api/audit").json()["events"])
    assert admin.get("/api/audit/verify").json()["ok"] is True
    assert "time_utc" in admin.get("/api/audit/export").text
    s = db.SessionLocal()
    row = s.query(AuditEvent).order_by(AuditEvent.id).first()
    row.actor = "someone-else@x.example"
    s.commit()
    s.close()
    v = admin.get("/api/audit/verify").json()
    assert v["ok"] is False and v["broken_at"] == row.id
