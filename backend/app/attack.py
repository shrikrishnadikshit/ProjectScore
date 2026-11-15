"""MITRE ATT&CK techniques that each kind of finding makes easier for an attacker.

This turns a technical issue into the attack it enables, in the shared language security teams already use
(https://attack.mitre.org). ATT&CK is free to use under the MITRE terms of use.
"""

from __future__ import annotations

T = {
    "T1133": "External Remote Services",
    "T1021": "Remote Services",
    "T1110": "Brute Force",
    "T1190": "Exploit Public-Facing Application",
    "T1496": "Resource Hijacking",
    "T1657": "Financial Theft",
    "T1189": "Drive-by Compromise",
    "T1566": "Phishing",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1557": "Adversary-in-the-Middle",
    "T1539": "Steal Web Session Cookie",
    "T1584.001": "Compromise Infrastructure: Domains",
    "T1584.005": "Compromise Infrastructure: Botnet",
    "T1071": "Application Layer Protocol (command and control)",
    "T1608.001": "Stage Capabilities: Upload Malware",
    "T1584": "Compromise Infrastructure",
    "T1078": "Valid Accounts",
    "T1589.001": "Gather Victim Identity Information: Credentials",
    "T1486": "Data Encrypted for Impact (ransomware)",
    "T1046": "Network Service Discovery",
    "T1555": "Credentials from Password Stores",
}

# Rules are checked in order; the first whose prefix matches the finding code wins.
RULES: list[tuple[str, list[str]]] = [
    ("rdp_exposed", ["T1133", "T1110", "T1486"]),
    ("vnc_exposed", ["T1133", "T1110"]),
    ("telnet_exposed", ["T1133", "T1110"]),
    ("smb_exposed", ["T1021", "T1486"]),
    ("netbios_exposed", ["T1021", "T1046"]),
    ("ftp_exposed", ["T1110", "T1190"]),
    ("snmp_exposed", ["T1046"]),
    ("db_exposed", ["T1190", "T1110"]),
    ("docker_api_exposed", ["T1190"]),
    ("ai_service_exposed", ["T1190", "T1496"]),
    ("ics_exposed", ["T1190"]),
    ("kev_exposed", ["T1190", "T1486"]),
    ("apache_path_traversal_kev", ["T1190", "T1486"]),
    ("slow_patch_", ["T1190"]),
    ("known_cves", ["T1190"]),
    ("openssl_heartbleed_risk", ["T1190", "T1557"]),
    ("spf_", ["T1566"]),
    ("dmarc_", ["T1566"]),
    ("dkim_", ["T1566"]),
    ("impersonation_", ["T1583.001", "T1566.002"]),
    ("lookalike_domain_mail", ["T1566", "T1583.001"]),
    ("lookalike_domain_web", ["T1583.001", "T1566"]),
    ("mta_sts_missing", ["T1557"]),
    ("tls_", ["T1557"]),
    ("cert_", ["T1557"]),
    ("hsts_missing", ["T1557"]),
    ("cookie_not_secure", ["T1539"]),
    ("session_cookie_not_httponly", ["T1539"]),
    ("csp_missing", ["T1189"]),
    ("dangling_cname", ["T1584.001"]),
    ("botnet_c2", ["T1584.005", "T1071"]),
    ("malware_hosting", ["T1608.001"]),
    ("malware_user_content", ["T1608.001"]),
    ("spamhaus_drop", ["T1584"]),
    ("attack_source", ["T1584"]),
    ("breach_", ["T1078", "T1589.001"]),
    ("ransomware_leak_", ["T1486", "T1657"]),
    ("infostealer_", ["T1078", "T1555"]),
]
SUFFIX_RULES: list[tuple[str, list[str]]] = [
    ("_vulnerable", ["T1189"]),        # vulnerable JavaScript libraries run in visitors' browsers
    ("_vulnerable_old", ["T1189"]),
    ("_eol", ["T1190"]),
    ("_outdated", ["T1190"]),
]


def techniques(code: str) -> list[dict]:
    ids = next((t for prefix, t in RULES if code.startswith(prefix)), None)
    if ids is None:
        ids = next((t for suffix, t in SUFFIX_RULES if code.endswith(suffix)), [])
    return [{"id": i, "name": T[i], "url": f"https://attack.mitre.org/techniques/{i.replace('.', '/')}/"} for i in ids]
