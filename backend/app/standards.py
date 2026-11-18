"""Recognised testing standards: how each finding maps to them, and how our testing follows them.

Every finding is tagged with:
- CWE (MITRE Common Weakness Enumeration) weakness IDs,
- the OWASP Top 10 (2021) category, for web findings,
- OWASP Web Security Testing Guide (WSTG v4.2) test IDs, for web findings,
alongside the MITRE ATT&CK techniques in attack.py. Each finding also carries an evidence record in the
spirit of the Berkeley Protocol on Digital Open Source Investigations: where it came from, when it was
collected, how, and a SHA-256 fingerprint of the stored evidence so later changes can be detected.
"""

from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter

router = APIRouter(prefix="/api")

CWE = {
    "CWE-284": "Improper Access Control", "CWE-287": "Improper Authentication",
    "CWE-290": "Authentication Bypass by Spoofing", "CWE-295": "Improper Certificate Validation",
    "CWE-298": "Improper Validation of Certificate Expiration", "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength", "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-522": "Insufficiently Protected Credentials", "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
    "CWE-668": "Exposure of Resource to Wrong Sphere", "CWE-672": "Operation on a Resource after Expiration or Release",
    "CWE-693": "Protection Mechanism Failure", "CWE-798": "Use of Hard-coded Credentials",
    "CWE-1004": "Sensitive Cookie Without 'HttpOnly' Flag", "CWE-1021": "Improper Restriction of Rendered UI Layers or Frames",
    "CWE-1104": "Use of Unmaintained Third Party Components", "CWE-1395": "Dependency on Vulnerable Third-Party Component",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor", "CWE-1188": "Initialization of a Resource with an Insecure Default",
}
OWASP = {
    "A01": "A01:2021 Broken Access Control", "A02": "A02:2021 Cryptographic Failures",
    "A05": "A05:2021 Security Misconfiguration", "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
}
WSTG = {
    "WSTG-INFO-02": "Fingerprint Web Server", "WSTG-INFO-08": "Fingerprint Web Application Framework",
    "WSTG-CONF-01": "Test Network Infrastructure Configuration", "WSTG-CONF-05": "Enumerate Infrastructure and Application Admin Interfaces",
    "WSTG-CONF-07": "Test HTTP Strict Transport Security", "WSTG-CONF-10": "Test for Subdomain Takeover",
    "WSTG-CONF-12": "Test for Content Security Policy", "WSTG-CRYP-01": "Testing for Weak Transport Layer Security",
    "WSTG-SESS-02": "Testing for Cookies Attributes", "WSTG-CLNT-09": "Testing for Clickjacking",
    "WSTG-ATHN-07": "Testing for Weak Password Policy",
}
_OUTDATED = (["CWE-1395", "CWE-1104"], "A06", ["WSTG-INFO-02", "WSTG-INFO-08"])
_EXPOSED = (["CWE-284", "CWE-668"], "A05", ["WSTG-CONF-01", "WSTG-CONF-05"])
_CLEARTEXT = (["CWE-319", "CWE-284"], "A02", ["WSTG-CONF-01"])
_SPOOF = (["CWE-290", "CWE-345"], None, [])
# (code prefix, (CWE ids, OWASP Top 10 id, WSTG ids)); the first match wins.
RULES: list[tuple[str, tuple]] = [
    ("tls_", (["CWE-326", "CWE-319"], "A02", ["WSTG-CRYP-01"])),
    ("cert_expired", (["CWE-298", "CWE-295"], "A02", ["WSTG-CRYP-01"])),
    ("cert_", (["CWE-295"], "A02", ["WSTG-CRYP-01"])),
    ("hsts_missing", (["CWE-319"], "A05", ["WSTG-CONF-07"])),
    ("csp_missing", (["CWE-693"], "A05", ["WSTG-CONF-12"])),
    ("xfo_missing", (["CWE-1021"], "A05", ["WSTG-CLNT-09"])),
    ("xcto_missing", (["CWE-693"], "A05", [])),
    ("cookie_not_secure", (["CWE-614"], "A05", ["WSTG-SESS-02"])),
    ("session_cookie_not_httponly", (["CWE-1004"], "A05", ["WSTG-SESS-02"])),
    ("kev_exposed", _OUTDATED), ("known_cves", _OUTDATED), ("apache_path_traversal_kev", _OUTDATED),
    ("openssl_heartbleed_risk", (["CWE-1395", "CWE-200"], "A06", ["WSTG-CRYP-01"])),
    ("slow_patch_", _OUTDATED),
    ("telnet_exposed", _CLEARTEXT), ("ftp_exposed", _CLEARTEXT),
    ("rdp_exposed", _EXPOSED), ("vnc_exposed", _EXPOSED), ("smb_exposed", _EXPOSED), ("netbios_exposed", _EXPOSED),
    ("snmp_exposed", (["CWE-1188", "CWE-284"], "A05", ["WSTG-CONF-01"])),
    ("db_exposed", _EXPOSED), ("docker_api_exposed", _EXPOSED), ("k8s_api_exposed", _EXPOSED),
    ("ics_exposed", _EXPOSED), ("ai_service_exposed", _EXPOSED),
    ("dangling_cname", (["CWE-672"], "A05", ["WSTG-CONF-10"])),
    ("spf_", _SPOOF), ("dmarc_", _SPOOF), ("dkim_", _SPOOF),
    ("mta_sts_missing", (["CWE-319"], None, [])),
    ("dnssec_missing", (["CWE-345"], None, [])),
    ("breach_", (["CWE-522"], "A07", ["WSTG-ATHN-07"])),
    ("infostealer_", (["CWE-522"], "A07", [])),
]
SUFFIX_RULES = [("_vulnerable", _OUTDATED), ("_vulnerable_old", _OUTDATED), ("_eol", _OUTDATED),
                ("_eol_old", _OUTDATED), ("_outdated", _OUTDATED)]


def tags(code: str) -> dict:
    hit = next((m for p, m in RULES if code.startswith(p)), None) or next((m for s, m in SUFFIX_RULES if code.endswith(s)), None)
    if not hit:
        return {"cwe": [], "owasp": None, "wstg": []}
    cwes, owasp, wstg = hit
    return {"cwe": [{"id": c, "name": CWE.get(c, c), "url": f"https://cwe.mitre.org/data/definitions/{c.split('-')[1]}.html"} for c in cwes],
            "owasp": {"id": owasp, "name": OWASP[owasp], "url": "https://owasp.org/Top10/"} if owasp else None,
            "wstg": [{"id": w, "name": WSTG.get(w, w), "url": "https://owasp.org/www-project-web-security-testing-guide/v42/"} for w in wstg]}


SOURCES = {"email_security": "Public DNS (SPF, DKIM, DMARC, MTA-STS records)", "dns_health": "Public DNS",
           "tls": "TLS handshake with the public server", "web_security": "HTTPS response from the public website",
           "vulnerability": "Service banners and versions seen from the internet", "network_exposure": "Internet exposure data (Shodan InternetDB)",
           "compromise": "Threat intelligence feeds", "brand": "Public DNS and the look-alike site's public page",
           "breach_history": "Public breach and infostealer catalogues"}


def provenance(f) -> dict:
    """Berkeley Protocol style record: source, method, collection times and a fingerprint of the evidence."""
    ev = f.evidence or {}
    canonical = json.dumps({"code": f.code, "asset": f.asset_value, "evidence": ev}, sort_keys=True, default=str)
    return {"source": ev.get("source") or SOURCES.get(f.risk_factor, "Passive internet observation"),
            "method": "active, authorised" if ev.get("active") else "passive (public information only)",
            "first_collected": f.first_seen.isoformat() if f.first_seen else None,
            "last_collected": f.last_seen.isoformat() if f.last_seen else None,
            "sha256": hashlib.sha256(canonical.encode()).hexdigest()}


# How each recognised standard is used. status: "applied" (our process follows it), "mapped" (findings or
# output are tagged with it), "referenced" (cited; it certifies people or is withdrawn, so software cannot apply it).
CATALOGUE = [
    {"area": "OSINT (open source intelligence)", "standards": [
        {"name": "OSINT Framework", "status": "applied", "how": "Our free sources are organised the same way: domains and DNS, IP and network, breaches, dark web, social and news."},
        {"name": "NIST SP 800-150 (Cyber Threat Information Sharing)", "status": "applied", "how": "Threat feeds we use (CISA KEV, abuse.ch, Spamhaus) follow its sharing model; findings can be exported through the API."},
        {"name": "SANS intelligence cycle", "status": "applied", "how": "Planning (scope from verified domains), collection (collectors), processing (normalised findings), analysis (scoring, attack paths), dissemination (reports, alerts)."},
        {"name": "Berkeley Protocol on Digital Open Source Investigations", "status": "applied", "how": "Each finding keeps its source, method, first and last collection time and a SHA-256 fingerprint of the evidence."},
    ]},
    {"area": "Web application security", "standards": [
        {"name": "OWASP Top 10 (2021)", "status": "mapped", "how": "Every web finding is tagged with its Top 10 category."},
        {"name": "OWASP ASVS", "status": "referenced", "how": "Vendor questionnaires ask about ASVS; our passive checks cover its configuration and transport controls only."},
        {"name": "OWASP WSTG (Web Security Testing Guide v4.2)", "status": "mapped", "how": "Findings carry the WSTG test IDs they correspond to (for example WSTG-CRYP-01, WSTG-SESS-02)."},
        {"name": "CWE (Common Weakness Enumeration)", "status": "mapped", "how": "Every finding with a software weakness is tagged with CWE IDs."},
    ]},
    {"area": "Penetration testing", "standards": [
        {"name": "PTES (Penetration Testing Execution Standard)", "status": "applied", "how": "In-depth scans follow its phases: pre-engagement (domain verification and written authorisation), intelligence gathering, threat modelling (attacker's view), vulnerability analysis, and reporting. Exploitation and post-exploitation are not performed."},
        {"name": "NIST SP 800-115 (Technical Guide to Information Security Testing)", "status": "applied", "how": "Planning, discovery, attack (limited to non-intrusive vulnerability checks) and reporting phases."},
        {"name": "OSSTMM", "status": "referenced", "how": "Its data-network channel informs our exposure checks; physical, human and wireless testing is out of scope for an online platform."},
        {"name": "CREST and OSCP", "status": "referenced", "how": "These certify people and companies, not software. Use CREST-accredited testers for manual penetration tests."},
    ]},
    {"area": "Port scanning and network discovery", "standards": [
        {"name": "RFC 793 (TCP) and RFC 768 (UDP)", "status": "applied", "how": "Open, closed and filtered ports are interpreted as these define. Active port scanning runs only on verified domains with written authorisation."},
        {"name": "MITRE ATT&CK Discovery (T1046 Network Service Discovery)", "status": "mapped", "how": "Exposed-service findings and attack paths carry ATT&CK technique IDs."},
        {"name": "NIST SP 800-42", "status": "referenced", "how": "Withdrawn by NIST and replaced by SP 800-115, which we follow."},
    ]},
    {"area": "IP address discovery", "standards": [
        {"name": "RFC 1918 and RFC 4291", "status": "applied", "how": "Private IPv4 and non-global IPv6 addresses are excluded and never contacted."},
        {"name": "RDAP (RFC 7480 to 7484)", "status": "applied", "how": "IP ownership and netblocks are found with RDAP, not WHOIS."},
        {"name": "BGP (RFC 4271)", "status": "applied", "how": "Each IP is mapped to its BGP origin network (ASN) and hosting provider through Team Cymru's IP-to-ASN service."},
    ]},
    {"area": "Source code reviews", "standards": [
        {"name": "OWASP Code Review Guide", "status": "applied", "how": "Automated stages it recommends: secrets, vulnerable dependencies and insecure code patterns (Gitleaks, OSV-Scanner, Bandit). Business-logic review needs a human reviewer."},
        {"name": "SEI CERT Secure Coding Standards", "status": "mapped", "how": "Results in C, C++ and Java files are tagged with the matching CERT rule where one exists (for example MSC41-C, MSC03-J for hard-coded secrets)."},
        {"name": "ISO/IEC 5055", "status": "referenced", "how": "Cited only: measuring against it needs a licensed, certified analyser."},
        {"name": "SARIF 2.1.0 (OASIS)", "status": "applied", "how": "Every code review can be downloaded as a SARIF 2.1.0 file, with CWE tags, for use in GitHub, Azure DevOps and other tools."},
    ]},
]


@router.get("/standards")
def standards() -> dict:
    return {"catalogue": CATALOGUE, "cwe": CWE, "owasp": OWASP, "wstg": WSTG}
