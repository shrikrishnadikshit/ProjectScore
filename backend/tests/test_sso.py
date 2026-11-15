import base64
import json
import time
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from app import auth, db, main, sso
from app.auth import create_user

PASSWORD = "correct-horse-battery"
TENANT = "11111111-2222-3333-4444-555555555555"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "Asha@Client.example", PASSWORD)
    s.close()


def token(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


def env(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "gid")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "gsecret")
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "mid")
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "msecret")


def flow(monkeypatch, provider, claims_fn):
    c = TestClient(main.app, follow_redirects=False)
    r = c.get(f"/api/auth/sso/{provider}/start")
    assert r.status_code == 302
    q = parse_qs(urlsplit(r.headers["location"]).query)
    assert q["code_challenge_method"] == ["S256"]
    claims = claims_fn(q["nonce"][0])
    monkeypatch.setattr(sso, "exchange_code", lambda p, code, v: {"id_token": token(claims)})
    return c, c.get(f"/api/auth/sso/{provider}/callback", params={"code": "abc", "state": q["state"][0]})


def test_providers_listed_only_when_configured(monkeypatch):
    assert TestClient(main.app).get("/api/auth/sso/providers").json() == []
    env(monkeypatch)
    assert [p["id"] for p in TestClient(main.app).get("/api/auth/sso/providers").json()] == ["google"]
    monkeypatch.setenv("MICROSOFT_ALLOWED_TENANTS", TENANT)
    assert len(TestClient(main.app).get("/api/auth/sso/providers").json()) == 2


def test_google_sign_in(monkeypatch):
    env(monkeypatch)
    good = lambda n: {"iss": "https://accounts.google.com", "aud": "gid", "nonce": n, "exp": time.time() + 300,
                      "email": "asha@client.example", "email_verified": True}
    c, r = flow(monkeypatch, "google", good)
    assert r.status_code == 302 and r.headers["location"] == "/"
    assert c.get("/api/auth/me").json()["email"].lower() == "asha@client.example"

    _, r = flow(monkeypatch, "google", lambda n: {**good(n), "email_verified": False})
    assert "sso_error=failed" in r.headers["location"]
    _, r = flow(monkeypatch, "google", lambda n: {**good(n), "nonce": "other"})
    assert "sso_error=failed" in r.headers["location"]
    _, r = flow(monkeypatch, "google", lambda n: {**good(n), "aud": "someone-else"})
    assert "sso_error=failed" in r.headers["location"]
    _, r = flow(monkeypatch, "google", lambda n: {**good(n), "email": "nobody@client.example"})
    assert "sso_error=no_account" in r.headers["location"]


def test_microsoft_requires_allowed_tenant(monkeypatch):
    env(monkeypatch)
    monkeypatch.setenv("MICROSOFT_ALLOWED_TENANTS", TENANT)
    claims = lambda tid: (lambda n: {"iss": f"https://login.microsoftonline.com/{tid}/v2.0", "aud": "mid", "nonce": n,
                                     "exp": time.time() + 300, "tid": tid, "email": "asha@client.example"})
    _, r = flow(monkeypatch, "microsoft", claims(TENANT))
    assert r.headers["location"] == "/"
    _, r = flow(monkeypatch, "microsoft", claims("99999999-0000-0000-0000-000000000000"))
    assert "sso_error=failed" in r.headers["location"]


def test_callback_without_state_cookie_fails(monkeypatch):
    env(monkeypatch)
    r = TestClient(main.app, follow_redirects=False).get("/api/auth/sso/google/callback", params={"code": "x", "state": "y"})
    assert "sso_error=expired" in r.headers["location"]
