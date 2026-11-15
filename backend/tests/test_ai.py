from fastapi.testclient import TestClient

from app import ai, auth, db, main, questionnaires, remediation, threatevents
from app.auth import create_user
from app.collectors import kev, network
from app.models import Finding, VendorDetection

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "member@c.example", PASSWORD)
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def test_ai_ports_flagged():
    assert not set(network.AI_PORTS) & set(network.RISKY_PORTS)
    out = network.evaluate_exposure("1.2.3.4", {"ports": [11434, 443, 8265]}, frozenset())
    codes = {f.code for f in out}
    assert codes == {"ai_service_exposed_11434", "ai_service_exposed_8265"}


def test_ai_threat_tagging():
    assert threatevents.is_ai({"vendorProject": "Langflow", "product": "Langflow"})
    assert threatevents.is_ai({"vendorProject": "NVIDIA", "product": "Triton Inference Server"})
    assert not threatevents.is_ai({"vendorProject": "Microsoft", "product": "Windows", "vulnerabilityName": "Windows Kernel"})
    assert not threatevents.is_ai({"vendorProject": "Fortinet", "product": "FortiOS", "shortDescription": "allows an attacker"})


def test_ai_guidance_and_questionnaire():
    assert remediation.guidance("ai_service_exposed_11434") is not remediation.DEFAULT
    q = dict((i, c) for i, _, _, c in questionnaires.QUESTIONS)
    assert q["ai4"] == ["ai_service_exposed"]


def test_ai_endpoint(monkeypatch):
    monkeypatch.setattr(kev, "kev_entries", lambda: [
        {"cveID": "CVE-2025-3248", "vendorProject": "Langflow", "product": "Langflow", "vulnerabilityName": "Langflow code injection",
         "dateAdded": "2099-01-01"},
        {"cveID": "CVE-2025-0001", "vendorProject": "Microsoft", "product": "Windows", "dateAdded": "2099-01-01"}])
    monkeypatch.setattr(threatevents, "recent", lambda entries, days, today=None: entries)
    user, other = login("member@c.example"), login("admin@o.example")
    eid = user.post("/api/entities", json={"name": "V", "primary_domain": "v.example"}).json()["id"]
    s = db.SessionLocal()
    s.add(Finding(entity_id=eid, asset_value="1.2.3.4", risk_factor="network_exposure", code="ai_service_exposed_11434",
                  title="AI service", severity="high", detection_confidence=0.6, evidence={"port": 11434, "ai": True}))
    s.add(VendorDetection(entity_id=eid, vendors=[{"name": "OpenAI", "domain": "openai.com", "category": "AI", "evidence": []},
                                                  {"name": "Slack", "domain": "slack.com", "category": "Collaboration", "evidence": []}]))
    s.commit()
    s.close()
    r = user.get(f"/api/entities/{eid}/ai").json()
    assert r["level"] == "high"
    assert r["exposed_services"][0]["port"] == 11434
    assert [v["name"] for v in r["ai_vendors"]] == ["OpenAI"]
    assert [e["cve"] for e in r["threat_events"]] == ["CVE-2025-3248"]
    assert r["attack_paths"][0]["id"] == "exposed_ai_service" and r["attack_paths"][0]["status"] == "open"
    assert {f["id"] for f in r["frameworks"]} >= {"eu_ai_act", "nist_ai_rmf", "iso42001"}
    assert other.get(f"/api/entities/{eid}/ai").status_code == 404
    t = user.get("/api/threat-events?ai_only=true").json()
    assert [e["cveID"] for e in t["events"]] == ["CVE-2025-3248"]
