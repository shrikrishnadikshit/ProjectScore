from datetime import date

from fastapi.testclient import TestClient

from app import auth, certin, db, main, remediation
from app.auth import create_user
from app.models import Alert, CertInItem, Finding

PASSWORD = "correct-horse-battery"

LIST_NOTES = """<table><tr><td><a href="s2cMainServlet?pageid=PUBVLNOTES01&amp;VLCODE=CIVN-2026-0558"><b>CERT-In Vulnerability Note CIVN-2026-0558</b></a>
<br>(November 17, 2026)<br><span>Multiple Vulnerabilities in N-Able Products</span></td></tr>
<tr><td><a href="s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2026-0557">CERT-In Vulnerability Note CIVN-2026-0557</a>
(November 16, 2026) Multiple Vulnerabilities in Apache HTTP Server</td></tr></table>
<a href="VulNotesList.jsp?next=20">Next &gt;&gt;</a>"""
LIST_ADV = """<a href="s2cMainServlet?pageid=PUBVLNOTES02&VLCODE=CIAD-2026-0061"><b>CERT-In Advisory CIAD-2026-0061</b></a> (November 18, 2026)
<p>Remote Code Execution Vulnerability in Oracle Java SE</p>"""
DETAIL = """<h3>CERT-In Vulnerability Note CIVN-2026-0557</h3><b>Multiple Vulnerabilities in Apache HTTP Server</b>
<p>Original Issue Date:November 16, 2026</p><p>Severity Rating: HIGH</p>
<p>Software Affected</p><ul><li>Apache HTTP Server versions prior to 2.4.66</li></ul>
<p>Overview</p><p>Multiple vulnerabilities...</p><p>CVE Name</p>
<a href="https://www.cve.org/CVERecord?id=CVE-2026-1111">CVE-2026-1111</a><a href="#">CVE-2026-2222</a>"""


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


def test_parse_list_and_detail():
    notes = certin.parse_list(LIST_NOTES)
    assert [(n["code"], n["issued"], n["title"]) for n in notes] == [
        ("CIVN-2026-0558", date(2026, 11, 17), "Multiple Vulnerabilities in N-Able Products"),
        ("CIVN-2026-0557", date(2026, 11, 16), "Multiple Vulnerabilities in Apache HTTP Server")]
    adv = certin.parse_list(LIST_ADV)
    assert adv[0]["code"] == "CIAD-2026-0061" and adv[0]["kind"] == "advisory" and adv[0]["title"].startswith("Remote Code")
    d = certin.parse_detail(DETAIL)
    assert d["severity"] == "high" and d["cves"] == ["CVE-2026-1111", "CVE-2026-2222"]
    assert d["products"] == ["Apache HTTP Server versions prior to 2.4.66"] and d["issued"] == date(2026, 11, 16)
    assert certin.url_for("CIAD-2026-0061").endswith("pageid=PUBVLNOTES02&VLCODE=CIAD-2026-0061")


def test_refresh_match_alert_and_feed():
    user, other = login("member@c.example"), login("admin@o.example")
    a = user.post("/api/entities", json={"name": "Alpha", "primary_domain": "alpha.example"}).json()["id"]
    b = user.post("/api/entities", json={"name": "Beta", "primary_domain": "beta.example"}).json()["id"]
    s = db.SessionLocal()
    s.add(Finding(entity_id=a, asset_value="1.2.3.4", risk_factor="vulnerability", code="known_cves", title="CVEs",
                  severity="medium", detection_confidence=0.5, evidence={"cves": ["CVE-2026-1111"]}))
    s.add(Finding(entity_id=b, asset_value="www.beta.example", risk_factor="vulnerability", code="apache_outdated",
                  title="Old Apache", severity="medium", detection_confidence=0.8, evidence={"software": "Apache/2.4.50"}))
    s.commit()

    def fetch(params):
        return {"VLNLIST02": LIST_NOTES, "PUBADVLIST02": LIST_ADV}.get(params["pageid"]) or (
            DETAIL if params.get("VLCODE") == "CIVN-2026-0557" else "<p>Severity Rating: CRITICAL</p>")

    assert certin.refresh(s, fetch=fetch, today=date(2026, 11, 18)) == 3
    assert certin.refresh(s, fetch=fetch, today=date(2026, 11, 18)) == 0
    alerts = s.query(Alert).filter_by(kind="certin").all()
    assert len(alerts) == 1 and "CIVN-2026-0557" in alerts[0].title and alerts[0].entity_id == a
    s.close()

    import app.certin as mod
    mod._state["last"] = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
    r = user.get("/api/certin?days=3650").json()
    item = next(i for i in r["items"] if i["code"] == "CIVN-2026-0557")
    assert item["affected"] == [{"id": a, "name": "Alpha", "match": "confirmed"}, {"id": b, "name": "Beta", "match": "same software"}]
    assert r["affected_companies"] == 2
    assert all(not i["affected"] for i in other.get("/api/certin?days=3650").json()["items"])
    e = user.get(f"/api/entities/{a}").json()
    assert e["certin"]["CVE-2026-1111"][0]["code"] == "CIVN-2026-0557"


def test_certin_reference():
    assert "AI_Security" in remediation.certin_reference("ai_service_exposed_11434")["url"]
    assert remediation.certin_reference("hsts_missing")["url"].endswith("GUIDLNVIEW01")
