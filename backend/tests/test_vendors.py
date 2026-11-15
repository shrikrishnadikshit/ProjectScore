from fastapi.testclient import TestClient

from app import auth, db, main, vendors
from app.auth import create_user
from app.models import Alert, Entity, Finding, Organization, VendorShare

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
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


RECORDS = {
    "mx": [("aspmx.l.google.com.", "acme.example")],
    "spf": [("_spf.google.com", "acme.example"), ("sendgrid.net", "acme.example"), ("unknown.example", "acme.example")],
    "txt": [("atlassian-domain-verification=abc", "acme.example"), ("MS=ms123456", "acme.example"),
            ("random text", "acme.example")],
    "ns": [("kate.ns.cloudflare.com.", "acme.example")],
    "cname": [("acme.zendesk.com.", "help.acme.example"), ("d111.cloudfront.net.", "cdn.acme.example")],
}


def test_classify():
    found = {v["name"]: v for v in vendors.classify(RECORDS, "acme.example")}
    assert set(found) == {"Google Workspace", "SendGrid (Twilio)", "Atlassian", "Microsoft 365", "Cloudflare",
                          "Zendesk", "Amazon Web Services"}
    assert len(found["Google Workspace"]["evidence"]) == 2  # MX and SPF
    assert found["Zendesk"]["evidence"][0]["seen_on"] == "help.acme.example"
    assert found["Cloudflare"]["domain"] == "cloudflare.com"
    # a company is never listed as its own vendor
    assert "Google Workspace" not in {v["name"] for v in vendors.classify(RECORDS, "google.com")}


def test_vendor_endpoints(monkeypatch):
    monkeypatch.setenv("VENDOR_DETECTION", "on")
    monkeypatch.setattr(vendors, "gather", lambda domain, hosts: RECORDS)
    user, other = login("member@c.example"), login("admin@o.example")
    a = user.post("/api/entities", json={"name": "Acme", "primary_domain": "acme.example"}).json()["id"]
    user.post("/api/entities", json={"name": "Cloudflare", "primary_domain": "cloudflare.com"})
    res = user.get(f"/api/entities/{a}/vendors").json()
    names = {v["name"]: v for v in res["vendors"]}
    assert names["Cloudflare"]["in_portfolio"] and not names["Zendesk"]["in_portfolio"]
    assert other.get(f"/api/entities/{a}/vendors").status_code == 404
    fp = user.get("/api/fourth-parties").json()
    assert fp["companies_checked"] == 1 and fp["companies_total"] == 2
    assert fp["vendors"][0]["used_by"][0]["name"] == "Acme"
    assert other.get("/api/fourth-parties").json()["vendors"] == []


def _finding(entity_id, title="No DMARC", code="dmarc_missing", severity="medium"):
    s = db.SessionLocal()
    f = Finding(entity_id=entity_id, asset_value="v.example", risk_factor="email_security", code=code, title=title,
                severity=severity, detection_confidence=1.0, evidence={})
    s.add(f)
    s.commit()
    fid = f.id
    s.close()
    return fid


def test_vendor_share_flow(monkeypatch):
    admin, member, other = login("admin@c.example"), login("member@c.example"), login("admin@o.example")
    eid = admin.post("/api/entities", json={"name": "Vendor", "primary_domain": "v.example"}).json()["id"]
    fid = _finding(eid)
    assert member.post(f"/api/entities/{eid}/vendor-shares", json={"recipient_email": "it@v.example"}).status_code == 403
    assert other.post(f"/api/entities/{eid}/vendor-shares", json={"recipient_email": "it@v.example"}).status_code == 404
    share = admin.post(f"/api/entities/{eid}/vendor-shares",
                       json={"recipient_email": "it@v.example", "message": "Please fix by month end"}).json()
    token = share["link_path"].split("/")[-1]

    anon = TestClient(main.app)
    page = anon.get(f"/api/public/vendor-share/{token}").json()
    assert page["company"] == "Vendor" and page["requested_by"] == "Client"
    assert page["findings"][0]["fix"] and page["findings"][0]["id"] == fid
    assert anon.put(f"/api/public/vendor-share/{token}/findings/{fid}", json={"status": "nope"}).status_code == 422
    r = anon.put(f"/api/public/vendor-share/{token}/findings/{fid}", json={"status": "fixed", "comment": "Added DMARC"})
    assert r.json()["status"] == "fixed"
    s = db.SessionLocal()
    from sqlalchemy import select
    assert s.scalars(select(Alert)).first().kind == "vendor_reply"
    s.close()
    listed = member.get(f"/api/entities/{eid}/vendor-shares").json()[0]
    assert listed["replies"] == 1 and listed["by_status"]["fixed"] == 1
    assert listed["findings"][0]["response"]["comment"] == "Added DMARC"
    assert other.get(f"/api/entities/{eid}/vendor-shares").status_code == 404

    jobs = []
    monkeypatch.setattr(main, "_scan_job", jobs.append)
    assert anon.post(f"/api/public/vendor-share/{token}/rescan").status_code == 202
    assert jobs == [eid]
    assert anon.post(f"/api/public/vendor-share/{token}/rescan").status_code == 429

    # a finding from another company cannot be answered through this link
    e2 = admin.post("/api/entities", json={"name": "X", "primary_domain": "x.example"}).json()["id"]
    f2 = _finding(e2)
    assert anon.put(f"/api/public/vendor-share/{token}/findings/{f2}", json={"status": "fixed"}).status_code == 404

    assert member.post(f"/api/vendor-shares/{share['id']}/revoke").status_code == 403
    assert admin.post(f"/api/vendor-shares/{share['id']}/revoke").json()["state"] == "revoked"
    assert anon.get(f"/api/public/vendor-share/{token}").status_code == 404


def test_bulk_import(monkeypatch):
    jobs = []
    monkeypatch.setattr(main, "_import_scans", jobs.append)
    admin, member = login("admin@c.example"), login("member@c.example")
    csv_text = ("Company,Website,Tier,Industry\n"
                "Acme,https://acme.example/,1,Banking and financial services\n"
                "Beta,beta.example,2,\n"
                "Bad,not a domain,3,\n"
                "Gamma,gamma.example,7,\n"
                "Acme again,acme.example,1,\n")
    assert member.post("/api/entities/import", json={"csv": csv_text}).status_code == 403
    r = admin.post("/api/entities/import", json={"csv": csv_text}).json()
    assert [a["domain"] for a in r["added"]] == ["acme.example", "beta.example"]
    assert {s["row"] for s in r["skipped"]} == {3, 4, 5}
    assert r["scans_queued"] == 2 and len(jobs[0]) == 2
    tiers = {e["primary_domain"]: e["tier"] for e in admin.get("/api/entities").json()}
    assert tiers == {"acme.example": 1, "beta.example": 2}
    assert admin.post("/api/entities/import", json={"csv": "foo,bar\n"}).status_code == 422
    # no header row: name, domain
    r2 = admin.post("/api/entities/import", json={"csv": "Delta,delta.example\nEps,eps.example\n", "scan": False}).json()
    assert len(r2["added"]) == 2 and r2["scans_queued"] == 0
