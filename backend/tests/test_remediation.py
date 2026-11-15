import re
from pathlib import Path

from fastapi.testclient import TestClient

from app import auth, db, main
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Entity
from app.remediation import DEFAULT, guidance
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "user@c.example", PASSWORD)
    s.close()


def test_every_known_code_has_guidance():
    src = "".join(p.read_text() for p in Path("app/collectors").glob("*.py"))
    codes = set(re.findall(r'"([a-z0-9]+(?:_[a-z0-9]+)+)"', src))
    finding_codes = {c for c in codes if c.endswith(("_missing", "_exposed", "_eol", "_outdated", "_vulnerable", "_kev",
                                                       "_risk", "_cname", "_expired", "_expiring", "_untrusted", "_protocol",
                                                       "_secure", "_httponly", "_c2", "_hosting", "_content", "_drop", "_source",
                                                       "_found", "_key", "_1024", "_all", "_multiple", "_weak", "_only", "_partial"))}
    missing = [c for c in finding_codes if guidance(c) is DEFAULT and not c.endswith(("_exposed",))]
    assert not missing, missing
    assert guidance("rdp_exposed_3389")["owner"] == "Network team"
    assert guidance("db_exposed_5432")["effort"] == "quick"
    assert guidance("lookalike_domain_mail") is not DEFAULT and guidance("breach_acme2025") is not DEFAULT
    assert guidance("slow_patch_php_eol") is not DEFAULT
    assert guidance("php_eol_old")["why"].startswith("Very old")


def test_plan_ranks_by_points():
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": "user@c.example", "password": PASSWORD})
    eid = c.post("/api/entities", json={"name": "V", "primary_domain": "v.example"}).json()["id"]
    s = db.SessionLocal()
    raw = [RawFinding("email_security", "dmarc_missing", "No DMARC", "high", "v.example"),
           RawFinding("web_security", "xcto_missing", "No nosniff", "info", "v.example"),
           RawFinding("tls", "cert_expired", "Expired", "high", "a.v.example"),
           RawFinding("tls", "cert_expired", "Expired", "high", "b.v.example")]
    scan_entity(s, s.get(Entity, eid), lambda e: (raw, {"email_security": 1, "web_security": 2, "tls": 2}))
    s.close()
    p = c.get(f"/api/entities/{eid}/remediation").json()
    assert p["after_all_fixes"] == 900 and p["current"] < p["after_quick_fixes"] <= 900
    assert p["items"][0]["points"] >= p["items"][-1]["points"]
    expired = next(i for i in p["items"] if i["code"] == "cert_expired")
    assert expired["assets"] == ["a.v.example", "b.v.example"] and expired["fix"]
    assert next(i for i in p["items"] if i["code"] == "xcto_missing")["points"] == 0
