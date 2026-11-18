import json
import socket

import httpx
from fastapi.testclient import TestClient

from app import auth, db, main, webhooks
from app.auth import create_user
from app.models import Alert, Organization

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    create_user(s, "Client", "member@c.example", PASSWORD)
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def resolver(ip):
    return lambda host, port, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


def test_signature_roundtrip():
    body = b'{"a":1}'
    h = webhooks.sign("whsec_x", body, ts=1000)
    assert webhooks.check_signature("whsec_x", body, h, now=1100)
    assert not webhooks.check_signature("whsec_y", body, h, now=1100)
    assert not webhooks.check_signature("whsec_x", b'{"a":2}', h, now=1100)
    assert not webhooks.check_signature("whsec_x", body, h, now=2000)  # too old
    assert not webhooks.check_signature("whsec_x", body, "garbage")


def test_only_public_https():
    assert not webhooks._public("http://example.com/x", resolver("93.184.216.34"))
    assert not webhooks._public("https://user:pw@example.com/x", resolver("93.184.216.34"))
    for ip in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1"):
        assert not webhooks._public("https://hooks.example.com/x", resolver(ip)), ip
    assert webhooks._public("https://hooks.example.com/x", resolver("93.184.216.34"))


def test_setup_and_send(monkeypatch):
    monkeypatch.setattr(webhooks, "_public", lambda url, resolver=None: url.startswith("https://"))
    admin, member = login("admin@c.example"), login("member@c.example")
    assert member.put("/api/integrations/webhook", json={"url": "https://h.example/x"}).status_code == 403
    assert admin.put("/api/integrations/webhook", json={"url": "http://h.example/x"}).status_code == 422
    r = admin.put("/api/integrations/webhook", json={"url": "https://h.example/x"}).json()
    secret = r["signing_secret"]
    assert secret.startswith("whsec_")
    listed = admin.get("/api/integrations").json()["webhook"]
    assert listed["connected"] and "whsec" not in json.dumps(listed)
    assert admin.put("/api/integrations/webhook", json={"url": "https://h.example/y"}).json()["signing_secret"] is None

    sent = []

    def poster(url, content, headers, **kw):
        sent.append((url, content, headers))
        return httpx.Response(200, request=httpx.Request("POST", url))

    s = db.SessionLocal()
    org = s.query(Organization).first()
    a = Alert(org_id=org.id, kind="score_drop", severity="warning", title="Vendor dropped", detail="d")
    s.add(a)
    s.commit()
    assert webhooks.send(s, org.id, webhooks.payload(a), poster=poster)
    url, body, headers = sent[0]
    assert url == "https://h.example/y" and json.loads(body)["type"] == "alert.score_drop"
    assert webhooks.check_signature(secret, body, headers[webhooks.HEADER])

    def failing(url, content, headers, **kw):
        return httpx.Response(500, request=httpx.Request("POST", url))

    assert not webhooks.send(s, org.id, webhooks.payload(a), poster=failing)
    assert admin.get("/api/integrations").json()["webhook"]["last_error"] == "Webhook: HTTP 500"
    s.close()
