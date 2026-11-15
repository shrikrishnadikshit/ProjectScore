import json
import subprocess
from datetime import timedelta

from fastapi.testclient import TestClient

from app import active, auth, db, main
from app.auth import create_user
from app.models import ActiveScan, DomainVerification

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    create_user(s, "Client", "member@c.example", PASSWORD)
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    assert c.post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 200
    return c


AUTH = {"domain": "client.example", "authoriser_name": "Priya Shah", "authoriser_title": "CISO", "confirm": True}


def test_verification_and_authorisation_gate(monkeypatch):
    started = []
    monkeypatch.setattr(active, "run_scan", lambda scan_id: started.append(scan_id))
    monkeypatch.setattr(active, "nuclei_available", lambda: True)
    a = login("admin@c.example")
    assert login("member@c.example").get("/api/verifications").status_code == 403

    # Not verified yet: refused.
    assert a.post("/api/active-scans", json=AUTH).status_code == 403
    v = a.post("/api/verifications", json={"domain": "https://www.Client.example/"}).json()
    assert v["domain"] == "client.example" and v["record_name"] == "_projectscore-verify.client.example"
    token_value = v["record_value"]

    monkeypatch.setattr(active, "txt_records", lambda name: ["some-other-record"])
    assert a.post(f"/api/verifications/{v['id']}/check").status_code == 409
    monkeypatch.setattr(active, "txt_records", lambda name: [token_value])
    assert a.post(f"/api/verifications/{v['id']}/check").json()["valid"] is True

    # Another organisation can't use this verification.
    assert login("admin@o.example").post("/api/active-scans", json=AUTH).status_code == 403
    # Must confirm and name the authoriser.
    assert a.post("/api/active-scans", json={**AUTH, "confirm": False}).status_code == 422
    assert a.post("/api/active-scans", json={**AUTH, "authoriser_name": ""}).status_code == 422

    r = a.post("/api/active-scans", json=AUTH)
    assert r.status_code == 202 and started == [r.json()["id"]]
    detail = a.get(f"/api/active-scans/{r.json()['id']}").json()
    assert "authorised by the organisation that owns client.example" in detail["authorisation_text"]
    assert detail["authoriser_name"] == "Priya Shah"
    # One per 24 hours.
    assert a.post("/api/active-scans", json=AUTH).status_code == 429


def test_expired_verification_refused(monkeypatch):
    monkeypatch.setattr(active, "nuclei_available", lambda: True)
    a = login("admin@c.example")
    v = a.post("/api/verifications", json={"domain": "client.example"}).json()
    s = db.SessionLocal()
    row = s.get(DomainVerification, v["id"])
    row.verified_at = active._now() - timedelta(days=91)
    s.commit()
    s.close()
    assert a.post("/api/active-scans", json=AUTH).status_code == 403


def test_runner_scope_and_results():
    s = db.SessionLocal()
    scan = ActiveScan(org_id=1, domain="client.example", requested_by=1, authoriser_name="P",
                      authoriser_title="CISO", authorisation_text="x")
    s.add(scan)
    s.commit()
    seen = {}

    def fake_runner(cmd, **kw):
        seen["cmd"] = cmd
        targets = open(cmd[cmd.index("-l") + 1]).read().split()
        seen["targets"] = targets
        out = cmd[cmd.index("-o") + 1]
        with open(out, "w") as fh:
            fh.write(json.dumps({"template-id": "git-config", "matched-at": "https://client.example/.git/config",
                                 "info": {"name": "Git config exposed", "severity": "medium",
                                          "classification": {"cve-id": None}}}) + "\n")
            fh.write(json.dumps({"template-id": "cve-x", "matched-at": "https://www.client.example/",
                                 "info": {"name": "Known CVE", "severity": "critical",
                                          "classification": {"cve-id": ["cve-2024-0001"]}}}) + "\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    active.run_scan(scan.id, discover=lambda d: ["api.client.example", "evil.other.example"], runner=fake_runner)
    s.refresh(scan)
    assert scan.status == "done"
    assert seen["targets"] == ["https://client.example", "https://www.client.example", "https://api.client.example"]
    assert "-exclude-tags" in seen["cmd"] and "dos" in seen["cmd"][seen["cmd"].index("-exclude-tags") + 1]
    assert [r["severity"] for r in scan.results] == ["critical", "medium"]
    assert scan.results[0]["cves"] == ["CVE-2024-0001"]
    s.close()


def test_runner_failure_and_restart_cleanup():
    s = db.SessionLocal()
    scan = ActiveScan(org_id=1, domain="client.example", requested_by=1, authoriser_name="P",
                      authoriser_title="CISO", authorisation_text="x")
    s.add(scan)
    s.commit()
    active.run_scan(scan.id, discover=lambda d: [],
                    runner=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "boom"))
    s.refresh(scan)
    assert scan.status == "failed" and "boom" in scan.error
    stuck = ActiveScan(org_id=1, domain="client.example", requested_by=1, authoriser_name="P",
                       authoriser_title="CISO", authorisation_text="x", status="running")
    s.add(stuck)
    s.commit()
    active.fail_interrupted_scans(s)
    s.refresh(stuck)
    assert stuck.status == "failed"
    s.close()
