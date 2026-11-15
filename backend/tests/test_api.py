import os
from datetime import timedelta

os.environ["DATABASE_URL"] = "sqlite:///./test_projectscore.db"

from fastapi.testclient import TestClient  # noqa: E402

from app import db, main  # noqa: E402
from app.collectors import RawFinding  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app.models import Entity, Finding  # noqa: E402
from app.scan import scan_entity  # noqa: E402


def setup_function():
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)


def fake_collector(findings):
    return lambda entity: (findings, {"email_security": 1, "tls": 2, "web_security": 2, "dns_health": 2})


def test_create_scan_and_read_score():
    client = TestClient(main.app)
    r = client.post("/entities", json={"name": "Example", "primary_domain": "https://Example.com/"})
    assert r.status_code == 201
    entity_id = r.json()["id"]
    assert client.post("/entities", json={"name": "Dup", "primary_domain": "example.com"}).status_code == 409
    assert client.post("/entities", json={"name": "Bad", "primary_domain": "not a domain"}).status_code == 422

    session = db.SessionLocal()
    entity = session.get(Entity, entity_id)
    scan_entity(session, entity, fake_collector([
        RawFinding("email_security", "dmarc_missing", "No DMARC record", "high", "example.com")]))
    first = client.get(f"/entities/{entity_id}").json()
    assert first["grade"] is not None and first["score"] < 900
    assert [x["code"] for x in first["findings"]] == ["dmarc_missing"]

    # Fixed on the next scan: the finding is remediated, then decays out of the score (BRS 7.4).
    scan_entity(session, entity, fake_collector([]))
    second = client.get(f"/entities/{entity_id}").json()
    assert second["findings"] == []
    finding = session.scalars(select(Finding)).one()
    assert finding.status == "remediated"
    finding.last_seen -= timedelta(days=90)
    session.commit()
    scan_entity(session, entity, fake_collector([]))
    session.close()
    third = client.get(f"/entities/{entity_id}").json()
    assert third["score"] > first["score"]
    assert len(client.get(f"/entities/{entity_id}/scores").json()) == 3
    assert client.get("/entities/999").status_code == 404


def test_scan_with_no_coverage_is_rejected():
    import pytest

    from app.scan import NothingAssessed

    session = db.SessionLocal()
    entity = Entity(name="Down", primary_domain="down.example")
    session.add(entity)
    session.commit()
    with pytest.raises(NothingAssessed):
        scan_entity(session, entity, lambda e: ([], {"email_security": 0, "tls": 0}))
    session.close()
