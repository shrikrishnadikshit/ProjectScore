from fastapi.testclient import TestClient

from app import auth, db, main
from app.auth import create_user

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    session = db.SessionLocal()
    create_user(session, "Platform", "owner@p.example", PASSWORD, role="owner")
    create_user(session, "Client A", "admin@a.example", PASSWORD, role="admin")
    create_user(session, "Client A", "member@a.example", PASSWORD)
    create_user(session, "Client B", "admin@b.example", PASSWORD, role="admin")
    session.close()


def login(email, password=PASSWORD):
    c = TestClient(main.app)
    r = c.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return c


def test_admin_sees_and_adds_only_own_org():
    a = login("admin@a.example")
    assert {u["email"] for u in a.get("/api/users").json()} == {"admin@a.example", "member@a.example"}
    r = a.post("/api/users", json={"email": "new@a.example", "name": "New"})
    assert r.status_code == 201 and r.json()["organization"] == "Client A"
    temp = r.json()["temporary_password"]
    assert len(temp) >= 12
    login("new@a.example", temp)
    assert a.post("/api/users", json={"email": "x@b.example", "organization": "Client B"}).status_code == 403
    assert a.post("/api/users", json={"email": "y@a.example", "role": "owner"}).status_code == 422


def test_members_cannot_manage_users():
    m = login("member@a.example")
    assert m.get("/api/users").status_code == 403
    assert m.post("/api/users", json={"email": "z@a.example"}).status_code == 403


def test_owner_manages_all_orgs_and_creates_new_client_org():
    o = login("owner@p.example")
    assert len(o.get("/api/users").json()) == 4
    r = o.post("/api/users", json={"email": "first@c.example", "organization": "Client C", "role": "admin"})
    assert r.status_code == 201 and r.json()["organization"] == "Client C"
    assert "Client C" in o.get("/api/organizations").json()


def test_deactivate_signs_user_out_and_blocks_login():
    a, m = login("admin@a.example"), login("member@a.example")
    member_id = next(u["id"] for u in a.get("/api/users").json() if u["email"] == "member@a.example")
    assert a.patch(f"/api/users/{member_id}", json={"active": False}).json()["active"] is False
    assert m.get("/api/auth/me").status_code == 401
    r = TestClient(main.app).post("/api/auth/login", json={"email": "member@a.example", "password": PASSWORD})
    assert r.status_code == 401
    a.patch(f"/api/users/{member_id}", json={"active": True})
    login("member@a.example")


def test_admin_cannot_touch_other_orgs_or_self():
    a, b = login("admin@a.example"), login("admin@b.example")
    member_id = next(u["id"] for u in a.get("/api/users").json() if u["email"] == "member@a.example")
    me_id = a.get("/api/auth/me").json()["id"]
    assert b.patch(f"/api/users/{member_id}", json={"active": False}).status_code == 404
    assert a.patch(f"/api/users/{me_id}", json={"active": False}).status_code == 422


def test_reset_and_change_password():
    a = login("admin@a.example")
    member_id = next(u["id"] for u in a.get("/api/users").json() if u["email"] == "member@a.example")
    temp = a.post(f"/api/users/{member_id}/reset-password").json()["temporary_password"]
    m = login("member@a.example", temp)
    assert m.post("/api/auth/password", json={"current_password": "wrong", "new_password": "x" * 12}).status_code == 403
    assert m.post("/api/auth/password", json={"current_password": temp, "new_password": "short"}).status_code == 422
    assert m.post("/api/auth/password", json={"current_password": temp, "new_password": "brand-new-password"}).status_code == 204
    login("member@a.example", "brand-new-password")


def test_bootstrap_promotes_existing_admin_to_owner(monkeypatch):
    monkeypatch.setenv("ADMIN_EMAIL", "admin@b.example")
    session = db.SessionLocal()
    auth.bootstrap_admin(session)
    from app.models import User
    from sqlalchemy import select
    assert session.scalars(select(User).where(User.email == "admin@b.example")).one().role == "owner"
    session.close()
