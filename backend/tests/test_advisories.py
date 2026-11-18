from datetime import date

import httpx
from fastapi.testclient import TestClient

from app import advisories, auth, db, main
from app.auth import create_user
from app.collectors import RawFinding
from app.models import CveIntel, Entity
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"

RECORD = {
    "cveMetadata": {"cveId": "CVE-2021-44228", "state": "PUBLISHED", "assignerShortName": "apache",
                    "datePublished": "2021-12-10T00:00:00"},
    "containers": {
        "cna": {"title": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
                "descriptions": [{"lang": "en", "value": "Apache Log4j2 2.0-beta9 through 2.15.0 ..."}],
                "affected": [{"vendor": "Apache Software Foundation", "product": "Apache Log4j2"},
                             {"vendor": "n/a", "product": "n/a"}]},
        "adp": [{"title": "CISA ADP Vulnrichment", "metrics": [
            {"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "active"}, {"Automatable": "yes"},
                                                               {"Technical Impact": "total"}]}}},
            {"other": {"type": "kev", "content": {"dateAdded": "2021-12-10"}}}]}]}}

GITHUB = [{"ghsa_id": "GHSA-jfh8-c2jp-5v3q", "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
           "summary": "Remote code injection in Log4j", "severity": "critical", "type": "reviewed",
           "vulnerabilities": [{"package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
                                "vulnerable_version_range": ">= 2.0-beta9, < 2.15.0", "first_patched_version": "2.15.0"}]}]

SIGHTINGS = {"metadata": {"count": 4, "page": 1, "per_page": 100},
             "data": [{"type": "seen", "creation_timestamp": "2026-10-01T10:00:00Z"},
                      {"type": "exploited", "creation_timestamp": "2026-11-01T10:00:00Z"},
                      {"type": "exploited", "creation_timestamp": "2026-09-01T10:00:00Z"},
                      {"type": "published-proof-of-concept", "creation_timestamp": "2026-08-01T10:00:00Z"}]}

FEED = """<?xml version="1.0"?><rss version="2.0"><channel>
<item><title>Siemens SIMATIC (Update A)</title><link>https://www.cisa.gov/news-events/ics-advisories/icsa-26-300-01</link>
<pubDate>Tue, 17 Nov 2026 12:00:00 +0000</pubDate><description>&lt;p&gt;ICSA-26-300-01 CVE-2021-44228 and cve-2024-0001&lt;/p&gt;</description></item>
<item><title>Phish</title><link>https://evil.example/x</link><pubDate>Tue, 17 Nov 2026 12:00:00 +0000</pubDate></item>
</channel></rss>"""


def test_parsers():
    r = advisories.parse_cve_record(RECORD)
    assert r["assigner"] == "apache" and r["products"] == ["Apache Software Foundation Apache Log4j2"]
    assert r["ssvc"] == {"exploitation": "active", "automatable": "yes", "technical_impact": "total"} and r["kev"]
    g = advisories.parse_github(GITHUB)
    assert g[0]["id"] == "GHSA-jfh8-c2jp-5v3q" and g[0]["packages"][0]["patched"] == "2.15.0"
    assert advisories.parse_github([{"ghsa_id": "GHSA-x", "vulnerabilities": [{"package": {"name": "p"},
                                                                               "first_patched_version": {"identifier": "1.2"}}]}])[0]["packages"][0]["patched"] == "1.2"
    s = advisories.parse_sightings(SIGHTINGS)
    assert s == {"counts": {"seen": 1, "exploited": 2, "published-proof-of-concept": 1}, "total": 4, "latest": "2026-11-01"}
    items = advisories.parse_feed(FEED, "ics")
    assert len(items) == 1 and items[0]["code"] == "ICSA-26-300-01"
    assert items[0]["cves"] == ["CVE-2021-44228", "CVE-2024-0001"] and items[0]["published"] == date(2026, 11, 17)
    assert advisories.parse_feed("not xml", "ics") == []


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    s.close()


def test_enrich_and_entity_output():
    calls = []

    def github(client, cve):
        calls.append(cve)
        req = httpx.Request("GET", "https://api.github.com")
        raise httpx.HTTPStatusError("limit", request=req, response=httpx.Response(403, request=req))

    n = advisories.enrich({"CVE-2021-44228", "CVE-2022-0001", "bad"},
                          record=lambda c, cve: advisories.parse_cve_record(RECORD) if cve == "CVE-2021-44228" else None,
                          github=github, sightings=lambda c, cve: advisories.parse_sightings(SIGHTINGS), pause=0)
    assert n == 2 and calls == ["CVE-2021-44228"]  # GitHub skipped after the rate limit
    assert advisories.enrich({"CVE-2021-44228"}, record=None, github=None, sightings=None, pause=0) == 0  # fresh

    s = db.SessionLocal()
    assert s.get(CveIntel, "CVE-2022-0001").record == {}
    advisories.refresh_cisa(s, fetch=lambda url: FEED)
    assert advisories.refresh_cisa(s, fetch=lambda url: FEED) == 0
    s.close()

    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": "admin@c.example", "password": PASSWORD})
    eid = c.post("/api/entities", json={"name": "V", "primary_domain": "vendor.example"}).json()["id"]
    s = db.SessionLocal()
    scan_entity(s, s.get(Entity, eid), lambda e: (
        [RawFinding("vulnerability", "vulnerable_software", "Old Log4j", "high", "vendor.example",
                    evidence={"cves": ["CVE-2021-44228"]})], {"vulnerability": 1}))
    s.close()
    ent = c.get(f"/api/entities/{eid}").json()
    a = ent["advisories"]["CVE-2021-44228"]
    assert a["ssvc"]["exploitation"] == "active" and a["cisa"][0]["code"] == "ICSA-26-300-01"
    assert a["sightings"]["counts"]["exploited"] == 2
    listing = c.get("/api/advisories?days=3650").json()
    assert listing["items"][0]["affected"] == [{"entity_id": eid, "name": "V"}] and listing["affected"] == 1
    d = c.get("/api/cves/cve-2021-44228").json()
    assert d["intel"]["assigner"] == "apache" and d["links"]["cve_org"].endswith("CVE-2021-44228")
    assert c.get("/api/cves/nope").status_code == 422
    assert len(c.get("/api/advisories/sources").json()["sources"]) >= 7
