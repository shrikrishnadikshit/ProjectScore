from fastapi.testclient import TestClient

from app import auth, db, frameworks, main, risk
from app.auth import create_user
from app.models import Score

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    create_user(s, "Client", "member@c.example", PASSWORD)
    create_user(s, "Solo", "solo@s.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def test_every_framework_maps_to_real_controls():
    for factor, m in frameworks.FACTOR_CONTROLS.items():
        for fw, ids in m.items():
            assert fw in frameworks.FRAMEWORKS, fw
            assert set(ids) <= set(frameworks.FRAMEWORKS[fw]["controls"]), (factor, fw, ids)
    assert {"nis2", "dora", "gdpr", "pci_dss", "soc2", "hipaa", "nydfs", "sec", "uk_ce", "apra", "mas_trm", "nca_ecc",
            "uae_ia", "cis_v8"} <= set(frameworks.FRAMEWORKS)
    assert frameworks.regions_for("DE") == ["global", "eu"] and frameworks.regions_for("GB") == ["global", "uk", "eu"]
    assert frameworks.regions_for(None) == ["global", "india"]


def test_settings_drive_frameworks_risk_and_currency(monkeypatch):
    monkeypatch.setattr(risk, "inr_rates", lambda: {**risk._with_pegs(risk.FALLBACK_RATES), "date": None, "source": "test"})
    admin, member = login("admin@c.example"), login("member@c.example")
    assert member.get("/api/org-settings").json()["country"] == "IN"
    assert member.put("/api/org-settings", json={"country": "US", "currency": "USD"}).status_code == 403
    assert admin.put("/api/org-settings", json={"country": "IR", "currency": "USD"}).status_code == 422
    assert admin.put("/api/org-settings", json={"country": "US", "currency": "XYZ"}).status_code == 422
    s = admin.put("/api/org-settings", json={"country": "us", "currency": "USD"}).json()
    assert s["country"] == "US" and s["breach_cost_usd_m"] == 9.36

    eid = admin.post("/api/entities", json={"name": "V", "primary_domain": "v.example"}).json()["id"]
    db_s = db.SessionLocal()
    db_s.add(Score(entity_id=eid, overall=700, grade="B", model_version="t", factors={}, trace={}))
    db_s.commit()
    db_s.close()
    r = member.get(f"/api/entities/{eid}/risk").json()
    assert r["default_currency"] == "USD" and r["assumptions"]["breach_cost_usd_m"] == 9.36
    assert {"GBP", "AED", "SAR", "JPY"} <= set(r["currencies"]["impact"])
    assert abs(r["currencies"]["impact"]["USD"] - 9_360_000) < 50_000
    fws = {f["key"]: f for f in member.get(f"/api/entities/{eid}/frameworks").json()}
    assert fws["hipaa"]["preferred"] and fws["nist_csf"]["preferred"] and not fws["rbi"]["preferred"]

    admin.put("/api/org-settings", json={"country": "GB", "currency": "GBP", "breach_cost_usd_m": 3.0})
    r = member.get(f"/api/entities/{eid}/risk").json()
    assert r["assumptions"]["breach_cost_usd_m"] == 3.0 and "own figure" in r["assumptions"]["breach_cost_source"]


def test_export_and_delete():
    admin, member = login("admin@c.example"), login("member@c.example")
    data = member.get("/api/account/export")
    assert data.status_code == 200 and "attachment" in data.headers["content-disposition"]
    assert data.json()["profile"]["email"] == "member@c.example"
    # the only admin of an organisation with other members must hand over first
    assert admin.post("/api/account/delete", json={"password": PASSWORD}).status_code == 409
    assert member.post("/api/account/delete", json={"password": "wrong-password-123"}).status_code == 403
    assert member.post("/api/account/delete", json={"password": PASSWORD}).status_code == 204
    assert member.get("/api/auth/me").status_code == 401
    again = TestClient(main.app)
    assert again.post("/api/auth/login", json={"email": "member@c.example", "password": PASSWORD}).status_code == 401
    solo = login("solo@s.example")
    assert solo.post("/api/account/delete", json={"password": PASSWORD}).status_code == 204
