from fastapi.testclient import TestClient

from app import auth, db, main
from app.auth import create_user

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "user@c.example", PASSWORD)
    s.close()


def test_security_headers():
    r = TestClient(main.app).get("/api/health")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_cross_site_post_refused():
    c = TestClient(main.app)
    body = {"email": "user@c.example", "password": PASSWORD}
    assert c.post("/api/auth/login", json=body, headers={"Origin": "https://evil.example"}).status_code == 403
    assert c.post("/api/auth/login", json=body, headers={"Origin": "http://testserver"}).status_code == 200
    assert c.post("/api/auth/login", json=body).status_code == 200  # no Origin (non-browser clients)
