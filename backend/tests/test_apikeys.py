from fastapi.testclient import TestClient

from app import auth, db, main
from app.auth import create_user

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


def test_api_key_lifecycle():
    admin, member, other = login("admin@c.example"), login("member@c.example"), login("admin@o.example")
    admin.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"})
    assert member.post("/api/api-keys", json={"name": "SIEM"}).status_code == 403
    created = admin.post("/api/api-keys", json={"name": "SIEM"}).json()
    key = created["key"]
    assert key.startswith("ps_") and "key" not in admin.get("/api/api-keys").json()[0]

    api = TestClient(main.app)
    h = {"Authorization": f"Bearer {key}"}
    assert [e["name"] for e in api.get("/api/entities", headers=h).json()] == ["V"]
    assert api.post("/api/entities", json={"name": "X", "primary_domain": "x.example"}, headers=h).status_code == 403
    assert api.get("/api/entities", headers={"Authorization": "Bearer ps_wrong"}).status_code == 401
    assert admin.get("/api/api-keys").json()[0]["last_used_at"] is not None

    assert other.post(f"/api/api-keys/{created['id']}/revoke").status_code == 404
    assert admin.post(f"/api/api-keys/{created['id']}/revoke").json()["revoked"] is True
    assert api.get("/api/entities", headers=h).status_code == 401
