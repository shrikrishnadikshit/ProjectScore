from fastapi.testclient import TestClient

from app import auth, db, freereport, main, optout
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Entity, OptOutRequest
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"
RAW = [RawFinding("email_security", "dmarc_missing", "No DMARC policy", "high", "mail.acme.example"),
       RawFinding("tls", "tls_old", "Old TLS version", "medium", "www.acme.example")]


def setup_function():
    auth.throttle._failures.clear()
    freereport.limiter.hits.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Platform", "owner@p.example", PASSWORD, role="owner")
    create_user(s, "Client", "user@c.example", PASSWORD)
    s.close()


def fake_scan(monkeypatch, calls):
    def run(session, entity):
        calls.append(entity.primary_domain)
        return scan_entity(session, entity, lambda e: (RAW, {"email_security": 1, "tls": 2}))
    monkeypatch.setattr(freereport, "scan_entity", run)


def form(**kw):
    return {"domain": "acme.example", "contact_email": "cto@acme.example", "name": "Asha",
            "organisation": "Acme", **kw}


def test_free_report_flow(monkeypatch):
    calls = []
    fake_scan(monkeypatch, calls)
    c = TestClient(main.app)
    assert c.post("/api/public/free-report", json=form(contact_email="me@gmail.com")).status_code == 422
    r = c.post("/api/public/free-report", json=form())
    assert r.status_code == 202
    rep = c.get(f"/api/public/free-report/{r.json()['token']}").json()
    assert rep["status"] == "ready" and rep["grade"] and rep["counts"]["high"] == 1
    assert [i["title"] for i in rep["top_issues"]] == ["No DMARC policy", "Old TLS version"]
    assert "acme.example" not in str(rep["top_issues"]) and "assets" not in rep

    # A second request within a week reuses the rating instead of scanning again.
    c.post("/api/public/free-report", json=form(contact_email="ciso@acme.example"))
    assert calls == ["acme.example"]

    assert c.get("/api/public/free-report/nope").status_code == 404
    assert c.post("/api/public/free-report", json=form()).status_code == 202
    assert c.post("/api/public/free-report", json=form()).status_code == 429  # 3 per IP per day


def test_leads_are_owner_only_and_opt_out_respected(monkeypatch):
    fake_scan(monkeypatch, [])
    c = TestClient(main.app)
    c.post("/api/public/free-report", json=form())
    s = db.SessionLocal()
    s.add(OptOutRequest(domain="blocked.example", contact_email="a@blocked.example", status="approved"))
    s.commit()
    s.close()
    assert c.post("/api/public/free-report",
                  json=form(domain="blocked.example", contact_email="a@blocked.example")).status_code == 409

    member = TestClient(main.app)
    member.post("/api/auth/login", json={"email": "user@c.example", "password": PASSWORD})
    assert member.get("/api/free-reports").status_code == 403
    owner = TestClient(main.app)
    owner.post("/api/auth/login", json={"email": "owner@p.example", "password": PASSWORD})
    leads = owner.get("/api/free-reports").json()
    assert leads[0]["contact_email"] == "cto@acme.example" and leads[0]["grade"]
