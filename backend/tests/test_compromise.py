import ipaddress
import json

from app.collectors import compromise
from app.scoring import ScoringFinding, compute_score

FEEDS = {
    "feodo": compromise.parse_feodo([{"ip_address": "203.0.113.5", "port": 443, "malware": "QakBot"}]),
    "urlhaus": compromise.parse_urlhaus(
        "# URLhaus online\nhttp://shop.acme.example/wp/x.exe\nhttps://files.acme.example/a\n"
        + "".join(f"https://cdn.acme.example/u{i}.bin\n" for i in range(12)) + "http://other.example/x\n"),
    "drop": compromise.parse_drop(
        json.dumps({"cidr": "198.51.100.0/24", "sblid": "SBL1"}) + "\n" + json.dumps({"type": "metadata"}) + "\n"),
    "blocklist_de": compromise.parse_ip_list("192.0.2.7\nnot-an-ip\n"),
}


def test_parsers():
    assert FEEDS["urlhaus"]["cdn.acme.example"] == 12
    assert FEEDS["drop"] == [(ipaddress.ip_network("198.51.100.0/24"), "SBL1")]
    assert FEEDS["blocklist_de"] == frozenset({"192.0.2.7"})


def test_evaluate_matches_ips_and_hosts():
    hosts = ["acme.example", "shop.acme.example", "cdn.acme.example", "other.example"]
    ips = {"203.0.113.5": True, "198.51.100.9": False, "192.0.2.7": False, "192.0.2.8": True}
    found = {(f.code, f.asset_value): f for f in compromise.evaluate(hosts, ips, "acme.example", FEEDS)}
    assert found[("botnet_c2", "203.0.113.5")].severity == "critical"
    assert found[("botnet_c2", "203.0.113.5")].detection_confidence == 1.0
    assert found[("spamhaus_drop", "198.51.100.9")].detection_confidence == 0.8
    assert ("attack_source", "192.0.2.7") in found
    assert found[("malware_hosting", "shop.acme.example")].severity == "high"
    assert found[("malware_user_content", "cdn.acme.example")].severity == "low"
    assert not any(a == "other.example" for _, a in found)  # out of scope
    assert not any(a == "192.0.2.8" for _, a in found)


def test_collect_not_assessed_without_feeds(monkeypatch):
    monkeypatch.setenv("COMPROMISE_FEEDS", "on")
    empty = {"feodo": None, "urlhaus": None, "drop": None, "blocklist_de": None}
    assert compromise.collect(["a.example"], {"192.0.2.1": False}, "a.example", empty) == ([], 0)
    _, checked = compromise.collect(["a.example"], {"192.0.2.1": False}, "a.example", FEEDS)
    assert checked == 2


def test_botnet_triggers_compromise_gate():
    clean = compute_score([], {"compromise": 4, "email_security": 1})
    bad = compute_score([ScoringFinding("compromise", "critical", "203.0.113.5", "botnet_c2")],
                        {"compromise": 4, "email_security": 1})
    assert clean["overall"] > 640 >= bad["overall"]
