from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import db, main
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Entity, Finding
from app.scan import NothingAssessed, scan_entity

PASSWORD = "correct-horse-battery"


def setup_function():
    main.auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    session = db.SessionLocal()
    create_user(session, "Org A", "a@a.example", PASSWORD, role="admin")
    create_user(session, "Org B", "b@b.example", PASSWORD)
    session.close()


def client_for(email):
    client = TestClient(main.app)
    r = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return client


def fake_collector(findings):
    return lambda entity: (findings, {"email_security": 1, "tls": 2, "web_security": 2, "dns_health": 2})


def test_requires_login():
    client = TestClient(main.app)
    assert client.get("/api/entities").status_code == 401
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/health").status_code == 200


def test_login_logout_and_throttle():
    client = TestClient(main.app)
    assert client.post("/api/auth/login", json={"email": "a@a.example", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "nobody@x.example", "password": "x"}).status_code == 401
    client = client_for("A@A.example")
    me = client.get("/api/auth/me").json()
    assert me["organization"] == "Org A" and me["role"] == "admin"
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me").status_code == 401

    for _ in range(5):
        client.post("/api/auth/login", json={"email": "b@b.example", "password": "wrong"})
    r = client.post("/api/auth/login", json={"email": "b@b.example", "password": PASSWORD})
    assert r.status_code == 429


def test_portfolios_are_private_but_scans_shared():
    a, b = client_for("a@a.example"), client_for("b@b.example")
    r = a.post("/api/entities", json={"name": "Example", "primary_domain": "https://Example.com/", "tier": 1})
    assert r.status_code == 201
    entity_id = r.json()["id"]
    assert a.post("/api/entities", json={"name": "Dup", "primary_domain": "example.com"}).status_code == 409
    assert a.post("/api/entities", json={"name": "Bad", "primary_domain": "not a domain"}).status_code == 422
    assert a.post("/api/entities", json={"name": "Bad", "primary_domain": "ok.example", "tier": 9}).status_code == 422

    # Org B cannot see Org A's portfolio entry.
    assert b.get("/api/entities").json() == []
    assert b.get(f"/api/entities/{entity_id}").status_code == 404
    assert b.post(f"/api/entities/{entity_id}/scan").status_code == 404

    session = db.SessionLocal()
    scan_entity(session, session.get(Entity, entity_id), fake_collector([
        RawFinding("email_security", "dmarc_missing", "No DMARC record", "high", "example.com")]))
    session.close()

    # Org B adds the same company: same entity, its own tier, existing score is reused.
    rb = b.post("/api/entities", json={"name": "Example Inc", "primary_domain": "example.com", "tier": 3}).json()
    assert rb["id"] == entity_id and rb["tier"] == 3 and rb["score"] is not None
    assert a.get(f"/api/entities/{entity_id}").json()["tier"] == 1

    # Removing from B's portfolio leaves A's intact.
    assert b.delete(f"/api/entities/{entity_id}").status_code == 204
    assert b.get("/api/entities").json() == []
    assert len(a.get("/api/entities").json()) == 1


def test_scan_cooldown():
    a = client_for("a@a.example")
    entity_id = a.post("/api/entities", json={"name": "E", "primary_domain": "e.example"}).json()["id"]
    session = db.SessionLocal()
    scan_entity(session, session.get(Entity, entity_id), fake_collector([]))
    session.close()
    r = a.post(f"/api/entities/{entity_id}/scan")
    assert r.status_code == 429 and "minutes" in r.json()["detail"]


def test_findings_remediate_and_decay():
    a = client_for("a@a.example")
    entity_id = a.post("/api/entities", json={"name": "E", "primary_domain": "example.com"}).json()["id"]
    session = db.SessionLocal()
    entity = session.get(Entity, entity_id)
    scan_entity(session, entity, fake_collector([
        RawFinding("email_security", "dmarc_missing", "No DMARC record", "high", "example.com")]))
    first = a.get(f"/api/entities/{entity_id}").json()
    assert first["score"] < 900 and [x["code"] for x in first["findings"]] == ["dmarc_missing"]

    scan_entity(session, entity, fake_collector([]))
    assert a.get(f"/api/entities/{entity_id}").json()["findings"] == []
    finding = session.scalars(select(Finding)).one()
    assert finding.status == "remediated"
    finding.last_seen -= timedelta(days=90)
    session.commit()
    scan_entity(session, entity, fake_collector([]))
    session.close()
    assert a.get(f"/api/entities/{entity_id}").json()["score"] > first["score"]
    assert len(a.get(f"/api/entities/{entity_id}/scores").json()) == 3


def test_admin_invites_member_to_own_org():
    a, b = client_for("a@a.example"), client_for("b@b.example")
    r = a.post("/api/users", json={"email": "new@a.example", "password": PASSWORD})
    assert r.status_code == 201 and r.json()["organization"] == "Org A"
    assert a.post("/api/users", json={"email": "short@a.example", "password": "short"}).status_code == 422
    assert b.post("/api/users", json={"email": "x@b.example", "password": PASSWORD}).status_code == 403


def test_scan_with_no_coverage_is_rejected():
    session = db.SessionLocal()
    entity = Entity(name="Down", primary_domain="down.example")
    session.add(entity)
    session.commit()
    with pytest.raises(NothingAssessed):
        scan_entity(session, entity, lambda e: ([], {"email_security": 0, "tls": 0}))
    session.close()
