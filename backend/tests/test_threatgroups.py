from fastapi.testclient import TestClient

from app import auth, db, main, threatgroups
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Entity, Finding
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.close()


def test_dataset_is_trimmed_attack():
    d = threatgroups.data()
    names = {p["name"] for p in d["profiles"]}
    assert {"Wizard Spider", "Conti", "LockBit 3.0"} <= names
    assert "MITRE" in d["notice"] and all(p["techniques"] for p in d["profiles"] if p["kind"] == "group")


def test_match_subtechniques_and_entry():
    f = Finding(entity_id=1, risk_factor="network_exposure", code="rdp_exposed", title="RDP open", severity="high",
                asset_value="1.2.3.4", status="open", evidence={})
    groups = threatgroups.exposure([f], limit=200)
    assert groups and all(any(h["id"].startswith("T1133") or h["entry"] for h in g["entry"]) for g in groups)
    assert threatgroups.exposure([], limit=5) == []


def test_api():
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": "admin@c.example", "password": PASSWORD})
    other = TestClient(main.app)
    other.post("/api/auth/login", json={"email": "admin@o.example", "password": PASSWORD})
    eid = c.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    s = db.SessionLocal()
    scan_entity(s, s.get(Entity, eid), lambda e: (
        [RawFinding("network_exposure", "rdp_exposed", "Remote desktop open", "high", "1.2.3.4")], {"network_exposure": 1}))
    s.close()
    mine = c.get(f"/api/entities/{eid}/threat-groups").json()
    assert mine["groups"] and mine["groups"][0]["entry"][0]["evidence"] == ["Remote desktop open"]
    assert other.get(f"/api/entities/{eid}/threat-groups").status_code == 404
    listing = c.get("/api/threat-groups").json()
    assert listing["groups"] > 20 and listing["profiles"][0]["vendors"][0]["name"] == "V"
    assert all(not p["vendors"] for p in other.get("/api/threat-groups").json()["profiles"])
    g = c.get("/api/threat-groups/g0102").json()
    assert g["name"] == "Wizard Spider" and g["techniques"] and g["software"]
    assert c.get("/api/threat-groups/G9999").status_code == 404
