from fastapi.testclient import TestClient

from app import auth, db, main, productsearch
from app.auth import create_user
from app.models import AssetProfile, Finding, Organization, VendorDetection

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def test_which_vendors_run_product(monkeypatch):
    monkeypatch.setattr(productsearch, "_kev_products", lambda: {"CVE-2023-34362": "Progress MOVEit Transfer"})
    admin, other = login("admin@c.example"), login("admin@o.example")
    a = admin.post("/api/entities", json={"name": "Alpha", "primary_domain": "alpha.example"}).json()["id"]
    b = admin.post("/api/entities", json={"name": "Beta", "primary_domain": "beta.example"}).json()["id"]
    s = db.SessionLocal()
    s.add(Finding(entity_id=a, asset_value="www.alpha.example", risk_factor="vulnerability", code="outdated_nginx",
                  title="Outdated web server", severity="medium", detection_confidence=0.8, evidence={"software": "nginx/1.14.0"}))
    s.add(Finding(entity_id=b, asset_value="files.beta.example", risk_factor="vulnerability", code="exposure_kev",
                  title="Exploited vulnerability", severity="critical", detection_confidence=0.8, evidence={"cves": ["CVE-2023-34362"]}))
    s.add(Finding(entity_id=b, asset_value="beta.example", risk_factor="web", code="js_outdated",
                  title="Outdated JavaScript library", severity="low", detection_confidence=0.9, evidence={"library": "jquery", "version": "1.12.4"}))
    s.add(VendorDetection(entity_id=a, vendors=[{"name": "Okta", "domain": "okta.com", "category": "Identity", "evidence": []}]))
    s.add(AssetProfile(entity_id=b, asset="1.2.3.4", kind="ip", value="medium", provider="Amazon AWS"))
    s.commit()
    s.close()

    def names(q):
        return [v["name"] for v in admin.get("/api/product-search", params={"q": q}).json()["vendors"]]

    assert names("nginx") == ["Alpha"]
    assert names("MOVEit") == ["Beta"]
    assert names("jQuery") == ["Beta"]
    assert names("okta") == ["Alpha"]
    assert names("amazon") == ["Beta"]
    assert names("sap hana") == []
    m = admin.get("/api/product-search", params={"q": "moveit"}).json()["vendors"][0]["matches"][0]
    assert "CVE-2023-34362" in m["what"]
    assert admin.get("/api/product-search", params={"q": "x"}).status_code == 422
    assert other.get("/api/product-search", params={"q": "nginx"}).json()["total"] == 0
    sug = {r["name"] for r in admin.get("/api/product-search/suggestions").json()}
    assert {"Okta", "nginx", "jquery"} <= sug
