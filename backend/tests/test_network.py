from app.collectors import kev, network


def codes(findings):
    return {f.code for f in findings}


RDAP_OWNED = {
    "handle": "NET-140-82-112-0-1", "name": "GITHUB-NET4",
    "cidr0_cidrs": [{"v4prefix": "140.82.112.0", "length": 20}],
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                     ["fn", {}, "text", "GitHub, Inc."]]]}],
}
RDAP_CLOUD = {
    "handle": "NET-3-0-0-0-1", "name": "AT-88-Z",
    "cidr0_cidrs": [{"v4prefix": "3.0.0.0", "length": 9}],
    "entities": [{"vcardArray": ["vcard", [["fn", {}, "text", "Amazon Technologies Inc."]]]}],
}


def test_rdap_ownership_matches_company_not_host():
    owned, cloud = network.parse_rdap(RDAP_OWNED), network.parse_rdap(RDAP_CLOUD)
    assert owned["cidrs"] == ["140.82.112.0/20"]
    assert network.is_owned(owned, "GitHub", "github.com")
    assert not network.is_owned(cloud, "GitHub", "github.com")
    # Generic words alone must not create a match.
    assert not network.is_owned(network.parse_rdap({"name": "GLOBAL-SERVICES-NET", "entities": []}),
                                "Global Services Ltd", "acme.example")


def test_exposure_findings_and_kev():
    data = {"ports": [22, 443, 3389, 3306, 502], "vulns": ["CVE-2021-44228", "cve-2020-0001"], "tags": []}
    found = network.evaluate_exposure("203.0.113.5", data, frozenset({"CVE-2021-44228"}))
    assert {"rdp_exposed_3389", "db_exposed_3306", "ics_exposed_502", "kev_exposed", "known_cves"} == codes(found)
    kev_f = next(f for f in found if f.code == "kev_exposed")
    assert kev_f.severity == "critical" and kev_f.evidence["kev"] is True and kev_f.evidence["cves"] == ["CVE-2021-44228"]
    assert network.evaluate_exposure("203.0.113.6", {"ports": [80, 443], "vulns": [], "tags": []}, frozenset()) == []


def test_kev_parse():
    assert kev.parse({"vulnerabilities": [{"cveID": "cve-2021-44228"}, {"x": 1}]}) == frozenset({"CVE-2021-44228"})


def test_collect_end_to_end_with_stubbed_sources(monkeypatch):
    monkeypatch.setenv("EXPOSURE_SOURCE", "internetdb")
    monkeypatch.setattr(network, "resolve_ips", lambda hosts: {"140.82.112.3": ["github.com"], "104.16.1.1": ["www.github.com"]})
    small_owned = {**RDAP_OWNED, "cidr0_cidrs": [{"v4prefix": "140.82.112.0", "length": 30}]}
    monkeypatch.setattr(network, "rdap_lookup",
                        lambda c, ip: network.parse_rdap(small_owned if ip.startswith("140.") else RDAP_CLOUD))
    exposures = {"140.82.112.3": {"ports": [443], "vulns": [], "tags": []},
                 "140.82.112.1": {"ports": [3389], "vulns": [], "tags": []},
                 "140.82.112.2": {"ports": [], "vulns": [], "tags": []},
                 "104.16.1.1": {"ports": [8080, 3306], "vulns": [], "tags": ["cdn"]}}
    monkeypatch.setattr(network, "exposure_lookup", lambda c, ip: exposures.get(ip))
    monkeypatch.setattr(kev, "kev_ids", lambda: frozenset())
    findings, coverage, assets = network.collect(["github.com", "www.github.com"], "GitHub", "github.com")
    assert codes(findings) == {"rdp_exposed_3389"}  # CDN edge ports ignored
    assert findings[0].asset_value == "140.82.112.1"
    assert ("netblock", "140.82.112.0/30") in assets and ("ip", "140.82.112.1") in assets
    assert coverage["network_exposure"] == 3


def test_collect_off():
    assert network.collect(["a.example"], "A", "a.example") == ([], {}, [])
