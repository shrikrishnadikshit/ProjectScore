from datetime import date, datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import attackpaths, auth, db, main
from app.auth import create_user
from app.models import Alert, DomainVerification, Finding, User

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Platform", "owner@p.example", PASSWORD, role="owner")
    admin = create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    create_user(s, "Client", "member@c.example", PASSWORD)
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.add(DomainVerification(org_id=admin.org_id, domain="client.example", token="t", created_by=admin.id,
                             verified_at=datetime.now(timezone.utc)))
    s.commit()
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


class F:
    def __init__(self, code, evidence=None, id=1):
        self.code, self.evidence, self.status, self.asset_value, self.id = code, evidence or {}, "open", "x", id
        self.title, self.severity = code, "high"


def test_attack_paths():
    none = attackpaths.paths([])
    assert none == []
    p = {x["id"]: x for x in attackpaths.paths([
        F("dmarc_missing"), F("lookalike_domain_mail"), F("breach_x", {"data_classes": ["Passwords"]}),
        F("rdp_exposed_3389"), F("csp_missing")])}
    assert p["phish_to_ransomware"]["status"] == "open"
    assert p["remote_access"]["status"] == "open"
    assert p["web_session_theft"]["status"] == "entry_point"  # no session-cookie weakness seen
    assert "exploit_public_app" not in p
    steps = p["phish_to_ransomware"]["steps"]
    assert steps[1]["technique"]["id"] == "T1566" and steps[-1]["state"] == "assumed"


def test_attack_paths_endpoint():
    user, other = login("member@c.example"), login("admin@o.example")
    eid = user.post("/api/entities", json={"name": "V", "primary_domain": "v.example"}).json()["id"]
    s = db.SessionLocal()
    s.add(Finding(entity_id=eid, asset_value="1.2.3.4", risk_factor="vulnerability", code="kev_exposed", title="KEV",
                  severity="critical", detection_confidence=1.0, evidence={"kev": True, "cves": ["CVE-1"]}))
    s.commit()
    s.close()
    r = user.get(f"/api/entities/{eid}/attack-paths").json()
    assert r[0]["id"] == "exploit_public_app" and r[0]["status"] == "open"
    assert other.get(f"/api/entities/{eid}/attack-paths").status_code == 404


def body(**kw):
    today = date.today()
    b = {"name": "Q1 red team", "objectives": "Reach customer database", "domains": ["client.example", "app.client.example"],
         "ip_ranges": ["34.120.0.0/24"], "exclusions": "payroll.client.example", "techniques": ["external_network", "phishing"],
         "window_start": today.isoformat(), "window_end": (today + timedelta(days=14)).isoformat(),
         "emergency_name": "Ravi", "emergency_phone": "+91 90000 00000", "emergency_email": "soc@client.example",
         "authoriser_name": "Asha", "authoriser_title": "CISO", "confirm": True}
    b.update(kw)
    return b


def test_request_rules():
    admin, member, other = login("admin@c.example"), login("member@c.example"), login("admin@o.example")
    assert member.post("/api/red-team", json=body()).status_code == 403
    assert admin.post("/api/red-team", json=body(confirm=False)).status_code == 422
    assert admin.post("/api/red-team", json=body(domains=["notmine.example"])).status_code == 422
    assert other.post("/api/red-team", json=body()).status_code == 422  # domain not verified by that org
    assert admin.post("/api/red-team", json=body(ip_ranges=["10.0.0.0/8"])).status_code == 422
    assert admin.post("/api/red-team", json=body(techniques=["nuke"])).status_code == 422
    assert admin.post("/api/red-team", json=body(window_end=(date.today() + timedelta(days=200)).isoformat())).status_code == 422
    r = admin.post("/api/red-team", json=body())
    assert r.status_code == 201
    e = r.json()
    assert "Asha (CISO)" in e["authorisation_text"] and "34.120.0.0/24" in e["authorisation_text"]
    assert e["status"] == "requested" and e["log"][0]["kind"] == "status"


def test_engagement_lifecycle():
    owner, admin, member, other = (login(x) for x in ("owner@p.example", "admin@c.example", "member@c.example", "admin@o.example"))
    eid = admin.post("/api/red-team", json=body()).json()["id"]
    assert other.get(f"/api/red-team/{eid}").status_code == 404
    assert [x["id"] for x in owner.get("/api/red-team").json()] == [eid]
    assert other.get("/api/red-team").json() == []
    assert admin.post(f"/api/red-team/{eid}/update", json={"status": "approved"}).status_code == 403

    # the customer's stop button blocks testing
    assert member.post(f"/api/red-team/{eid}/pause", json={"paused": True, "reason": "SOC investigating"}).json()["paused"]
    assert owner.post(f"/api/red-team/{eid}/update", json={"status": "in_progress"}).status_code == 409
    member.post(f"/api/red-team/{eid}/pause", json={"paused": False})
    assert owner.post(f"/api/red-team/{eid}/update", json={"status": "in_progress", "note": "Recon started from 198.51.100.7"}).json()["status"] == "in_progress"

    assert owner.post(f"/api/red-team/{eid}/findings", json={"title": "x", "severity": "high", "techniques": ["bad"],
                                                             "description": "d", "recommendation": "r"}).status_code == 422
    e = owner.post(f"/api/red-team/{eid}/findings", json={
        "title": "VPN accepts leaked password", "severity": "critical", "stage": "Initial access",
        "techniques": ["T1133", "t1078"], "asset": "vpn.client.example", "description": "Logged in with a breached password.",
        "evidence": "Screenshot ref 3", "recommendation": "Enforce MFA on the VPN."}).json()
    f = e["findings"][0]
    assert f["techniques"][1]["id"] == "T1078" and f["techniques"][0]["name"] == "External Remote Services"
    assert member.post(f"/api/red-team/{eid}/findings/{f['id']}/status", json={"status": "retest_passed"}).status_code == 403
    member.post(f"/api/red-team/{eid}/findings/{f['id']}/status", json={"status": "fix_claimed", "note": "MFA enforced"})
    e = owner.post(f"/api/red-team/{eid}/findings/{f['id']}/status", json={"status": "retest_passed"}).json()
    assert e["findings"][0]["status"] == "retest_passed" and e["open_findings"] == 0
    owner.post(f"/api/red-team/{eid}/update", json={"status": "closed", "summary": "Two paths to the crown jewels."})
    detail = member.get(f"/api/red-team/{eid}").json()
    assert detail["summary"].startswith("Two") and any("PAUSED" in l["text"] for l in detail["log"])
    s = db.SessionLocal()
    kinds = {a.kind for a in s.scalars(select(Alert))}
    assert "red_team" in kinds
    s.close()
    assert member.post(f"/api/red-team/{eid}/cancel", json={}).status_code == 403
