from app import cves, db
from app.collectors import RawFinding
from app.models import CveInfo, Entity, Finding
from app.scan import scan_entity

NVD = {"vulnerabilities": [{"cve": {"id": "CVE-2021-41773",
       "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49"}],
       "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH",
                                                                     "vectorString": "CVSS:3.1/AV:N/AC:L"}}],
                   "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}}]}}}]}


def setup_function():
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)


def test_parsers():
    p = cves.parse_nvd(NVD)
    assert p["cvss"] == 7.5 and p["cvss_version"] == "3.1" and p["cvss_severity"] == "high"
    assert cves.parse_nvd({"vulnerabilities": []}) is None
    assert cves.parse_epss({"data": [{"cve": "cve-2021-41773", "epss": "0.97", "percentile": "0.999"}]}) == {
        "CVE-2021-41773": (0.97, 0.999)}
    assert cves.severity_for(9.8, "medium") == "high" and cves.severity_for(5.0, "medium") == "low"
    assert cves.severity_for(None, "medium") == "medium"


def test_enrich_and_severity_from_cvss():
    n = cves.enrich({"CVE-2021-41773", "CVE-2023-0001", "not-a-cve"},
                    nvd=lambda c, cve: {**cves.parse_nvd(NVD), "cvss": 9.8} if cve == "CVE-2021-41773" else None,
                    epss=lambda c, ids: {"CVE-2021-41773": (0.97, 0.999)}, pause=0)
    assert n == 2
    s = db.SessionLocal()
    assert s.get(CveInfo, "CVE-2021-41773").epss == 0.97 and s.get(CveInfo, "CVE-2023-0001").cvss is None
    # Fresh data is not fetched again.
    assert cves.enrich({"CVE-2021-41773"}, nvd=lambda *a: 1 / 0, epss=lambda *a: {}, pause=0) == 0

    e = Entity(name="V", primary_domain="v.example")
    s.add(e)
    s.commit()
    raw = [RawFinding("vulnerability", "known_cves", "Exposed software with 2 published vulnerabilities", "medium",
                      "203.0.113.9", {"cves": ["CVE-2021-41773", "CVE-2023-0001"]}, 0.5)]
    scan_entity(s, e, lambda x: (raw, {"vulnerability": 1}))
    f = s.query(Finding).one()
    assert f.severity == "high" and f.evidence["max_cvss"] == 9.8
    s.close()
