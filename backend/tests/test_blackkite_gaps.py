from datetime import date, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import attack, auth, db, main, ransomware, risk, threatevents
from app.auth import create_user
from app.certificates import send_reminders
from app.collectors import kev
from app.models import Alert, Finding, Score

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "user@c.example", PASSWORD)
    create_user(s, "Other", "user@o.example", PASSWORD)
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def add_finding(entity_id, code, risk_factor="network_exposure", severity="high", evidence=None, asset="1.2.3.4"):
    s = db.SessionLocal()
    s.add(Finding(entity_id=entity_id, asset_value=asset, risk_factor=risk_factor, code=code, title=code,
                  severity=severity, detection_confidence=1.0, evidence=evidence or {}))
    s.commit()
    s.close()


def test_attack_mapping():
    assert [t["id"] for t in attack.techniques("rdp_exposed_3389")] == ["T1133", "T1110", "T1486"]
    assert attack.techniques("dmarc_missing")[0]["name"] == "Phishing"
    assert attack.techniques("lodash_vulnerable")[0]["id"] == "T1189"
    assert attack.techniques("xfo_missing") == []
    assert attack.techniques("T1584.001".lower()) == [] and "T1584/001" in attack.techniques("dangling_cname")[0]["url"]


def test_ransomware_index_rises_with_signals():
    class F:
        def __init__(self, code, evidence=None):
            self.code, self.evidence, self.status, self.asset_value = code, evidence or {}, "open", "x"
    clean = ransomware.susceptibility([], None)
    bad = ransomware.susceptibility([F("rdp_exposed_3389"), F("kev_exposed", {"kev": True}), F("dmarc_missing")],
                                    "Healthcare and pharma")
    assert clean["index"] < 0.1 and clean["level"] == "low"
    assert bad["index"] > 0.8 and bad["level"] == "critical"
    assert {s["id"] for s in bad["signals"]} == {"remote_access", "exploited_vuln", "phishing", "industry"}


def test_ransomware_endpoints():
    user, other = login("user@c.example"), login("user@o.example")
    eid = user.post("/api/entities", json={"name": "V", "primary_domain": "v.example"}).json()["id"]
    add_finding(eid, "smb_exposed_445")
    r = user.get(f"/api/entities/{eid}/ransomware").json()
    assert r["signals"][0]["id"] == "remote_access" and r["signals"][0]["examples"] == ["1.2.3.4"]
    assert other.get(f"/api/entities/{eid}/ransomware").status_code == 404
    assert user.get("/api/ransomware").json()[0]["entity_id"] == eid
    assert other.get("/api/ransomware").json() == []
    f = user.get(f"/api/entities/{eid}").json()["findings"][0]
    assert f["attack"][0]["id"] == "T1021"


def test_fair_simulation_shape():
    low = risk.fair_simulation(0.02, 10.0, 0.05)
    high = risk.fair_simulation(0.3, 10.0, 0.8)
    assert low["mean_crore"] < high["mean_crore"]
    assert high["p99_crore"] >= high["p95_crore"] >= high["p90_crore"] >= high["median_crore"]
    probs = [p["probability"] for p in high["exceedance"]]
    assert probs == sorted(probs, reverse=True)
    assert risk.fair_simulation(0.1, 10.0, 0.2, seed=3) == risk.fair_simulation(0.1, 10.0, 0.2, seed=3)
    assert high["by_scenario"]["ransomware"] > 0


def test_risk_endpoint_includes_fair(monkeypatch):
    monkeypatch.setattr(risk, "inr_rates", lambda: {"USD": 88.0, "EUR": 102.0, "date": None, "source": "test"})
    user = login("user@c.example")
    eid = user.post("/api/entities", json={"name": "V", "primary_domain": "v.example"}).json()["id"]
    s = db.SessionLocal()
    s.add(Score(entity_id=eid, overall=600, grade="C", model_version="t", factors={}, trace={}))
    s.commit()
    s.close()
    r = user.get(f"/api/entities/{eid}/risk").json()
    assert r["fair"]["simulations"] == 10000 and "USD" in r["fair"]["currencies"]["p95_crore"]


ENTRIES = [
    {"cveID": "CVE-2026-0001", "vendorProject": "Apache", "product": "HTTP Server", "vulnerabilityName": "Path traversal",
     "dateAdded": (date.today() - timedelta(days=3)).isoformat(), "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2026-0002", "vendorProject": "Acme", "product": "Router", "vulnerabilityName": "RCE",
     "dateAdded": (date.today() - timedelta(days=5)).isoformat(), "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2019-0003", "vendorProject": "Old", "product": "Thing", "vulnerabilityName": "Old",
     "dateAdded": "2019-01-01", "knownRansomwareCampaignUse": "Unknown"},
]


def test_threat_events(monkeypatch):
    monkeypatch.setattr(kev, "kev_entries", lambda: ENTRIES)
    user, other = login("user@c.example"), login("user@o.example")
    a = user.post("/api/entities", json={"name": "Alpha", "primary_domain": "alpha.example"}).json()["id"]
    b = user.post("/api/entities", json={"name": "Beta", "primary_domain": "beta.example"}).json()["id"]
    add_finding(a, "known_cves", "vulnerability", "medium", {"cves": ["CVE-2026-0002"]})
    add_finding(b, "apache_outdated", "vulnerability", "medium", {"software": "apache/2.4.41"}, "www.beta.example")
    r = user.get("/api/threat-events").json()
    assert [e["cveID"] for e in r["events"]] == ["CVE-2026-0001", "CVE-2026-0002"]
    apache, router = r["events"]
    assert apache["ransomware"] and apache["affected"] == [{"id": b, "name": "Beta", "match": "same software"}]
    assert router["affected"] == [{"id": a, "name": "Alpha", "match": "confirmed"}]
    assert r["affected_companies"] == 2
    assert all(not e["affected"] for e in other.get("/api/threat-events").json()["events"])


def test_certificates_and_reminders():
    user, other = login("user@c.example"), login("user@o.example")
    eid = user.post("/api/entities", json={"name": "V", "primary_domain": "v.example"}).json()["id"]
    soon = (date.today() + timedelta(days=10)).isoformat()
    assert user.post(f"/api/entities/{eid}/certificates", json={"kind": "nope"}).status_code == 422
    assert user.post(f"/api/entities/{eid}/certificates", json={"kind": "iso27001", "issued_on": soon,
                                                                "expires_on": "2020-01-01"}).status_code == 422
    c = user.post(f"/api/entities/{eid}/certificates", json={"kind": "iso27001", "issuer": "BSI", "expires_on": soon}).json()
    assert c["status"] == "expiring" and c["days_left"] == 10
    assert other.post(f"/api/entities/{eid}/certificates", json={"kind": "iso27001"}).status_code == 404
    assert other.put(f"/api/certificates/{c['id']}", json={"kind": "soc2_type2"}).status_code == 404
    add_finding(eid, "kev_exposed", "vulnerability", "critical")
    listed = user.get(f"/api/entities/{eid}/certificates").json()
    assert listed["warnings"] and listed["certificates"][0]["issuer"] == "BSI"
    summary = user.get("/api/certificates").json()
    assert summary["expiring"] == 1 and summary["without_any"] == []
    s = db.SessionLocal()
    assert send_reminders(s) == 1 and send_reminders(s) == 0
    assert s.scalars(select(Alert)).first().kind == "certificate"
    s.close()
    assert user.delete(f"/api/certificates/{c['id']}").status_code == 204
