from datetime import datetime, timezone

from app import active, codereview, standards
from app.models import ActiveScan, CodeReview, Finding


def test_tags():
    t = standards.tags("tls_old_protocol")
    assert [c["id"] for c in t["cwe"]] == ["CWE-326", "CWE-319"] and t["owasp"]["id"] == "A02" and t["wstg"][0]["id"] == "WSTG-CRYP-01"
    assert standards.tags("jquery_vulnerable")["owasp"]["id"] == "A06"
    assert standards.tags("db_exposed_5432")["cwe"][0]["id"] == "CWE-284"
    assert standards.tags("session_cookie_not_httponly")["cwe"][0]["id"] == "CWE-1004"
    assert standards.tags("dmarc_missing")["owasp"] is None and standards.tags("botnet_c2") == {"cwe": [], "owasp": None, "wstg": []}
    for _, (cwes, owasp, wstg) in standards.RULES:
        assert all(c in standards.CWE for c in cwes) and (owasp is None or owasp in standards.OWASP)
        assert all(w in standards.WSTG for w in wstg)
    assert {a["area"] for a in standards.CATALOGUE} >= {"Source code reviews", "Penetration testing"}


def test_provenance_fingerprint_changes_with_evidence():
    now = datetime(2026, 11, 18, tzinfo=timezone.utc)
    f = Finding(code="hsts_missing", asset_value="a.example", risk_factor="web_security", evidence={"x": 1},
                first_seen=now, last_seen=now)
    p1 = standards.provenance(f)
    f.evidence = {"x": 2}
    p2 = standards.provenance(f)
    assert len(p1["sha256"]) == 64 and p1["sha256"] != p2["sha256"]
    assert p1["source"].startswith("HTTPS") and p1["method"].startswith("passive")


def test_sarif():
    r = CodeReview(id=1, name="my repo", source="x", results=[
        {"tool": "Gitleaks", "rule": "aws-key", "severity": "high", "title": "Secret", "file": "src/Main.java", "line": 3},
        {"tool": "Bandit", "rule": "B602 subprocess_popen_with_shell_equals_true", "severity": "high", "title": "shell",
         "file": "a.py", "line": 9, "detail": "Confidence: high; CWE-78"},
        {"tool": "OSV-Scanner", "rule": "GHSA-1", "severity": "medium", "title": "lib 1.0", "file": "requirements.txt", "cves": ["CVE-1"]},
    ])
    s = codereview.to_sarif(r)
    assert s["version"] == "2.1.0" and len(s["runs"]) == 3
    runs = {x["tool"]["driver"]["name"]: x for x in s["runs"]}
    g = runs["Gitleaks"]
    assert g["results"][0]["properties"]["sei_cert"] == ["MSC03-J"] and "CWE-798" in g["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert runs["Bandit"]["results"][0]["properties"]["cwe"] == ["CWE-78"]
    assert runs["Bandit"]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 9
    assert runs["OSV-Scanner"]["results"][0]["level"] == "warning"


def test_active_phases_and_cwe():
    res = active.parse_results(['{"template-id":"t","info":{"name":"n","severity":"high","classification":{"cwe-id":["cwe-79"]}},"host":"h"}'])
    assert res[0]["cwe"] == ["CWE-79"]
    s = ActiveScan(status="done", targets=["a", "b"], results=res, authoriser_name="Ravi")
    ph = active.phases(s)
    assert ph[0]["ptes"] == "Pre-engagement" and "Ravi" in ph[0]["detail"]
    assert any(p["state"] == "not performed" for p in ph)
