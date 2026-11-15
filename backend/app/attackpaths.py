"""Attacker's view: the routes a real attacker would most likely try against a company.

A red team thinks in chains, not single issues: "spoof the CEO's email, phish a password, log in to the
VPN, deploy ransomware". We assemble the company's open findings into the common attack paths, step by
step along the MITRE ATT&CK stages, and say which steps we can see evidence for. A path where every step
has evidence is "open"; one with the entry step but not the rest is "partly open". This uses only the
passive findings we already have: nothing is attacked.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .attack import T
from .models import Finding, User

router = APIRouter(prefix="/api")


def _code(*prefixes):
    return lambda f: f.code.startswith(prefixes)


def _kev(f):
    return f.code in ("kev_exposed", "apache_path_traversal_kev") or (f.evidence or {}).get("kev") is True


def _passwords(f):
    return f.code.startswith("breach_") and any("password" in c.lower() for c in (f.evidence or {}).get("data_classes", []))


# Each path: (id, name, impact, [(stage, technique, step text, test or None when assumed, required)])
PATHS = [
    ("phish_to_ransomware", "Phishing email leading to ransomware",
     "An attacker sends email that looks like it comes from the company, steals a password and spreads ransomware.", [
         ("Resource development", "T1583.001", "Register a look-alike domain", _code("lookalike_domain_mail", "lookalike_domain_web"), False),
         ("Initial access", "T1566", "Send convincing email as the company (spoofing not blocked)",
          _code("spf_missing", "spf_pass_all", "spf_weak", "dmarc_missing", "dmarc_monitor_only", "dmarc_partial"), True),
         ("Credential access", "T1078", "Reuse passwords already leaked in a breach", _passwords, False),
         ("Impact", "T1486", "Encrypt systems for ransom", None, False),
     ]),
    ("remote_access", "Break-in through exposed remote access",
     "Remote desktop or file sharing open to the internet is guessed or brute-forced, then used to take over the network.", [
         ("Reconnaissance", "T1046", "Find remote access services open to the internet",
          _code("rdp_exposed", "vnc_exposed", "telnet_exposed", "smb_exposed", "netbios_exposed"), True),
         ("Credential access", "T1110", "Guess or reuse passwords", _passwords, False),
         ("Initial access", "T1133", "Log in remotely", _code("rdp_exposed", "vnc_exposed", "telnet_exposed"), False),
         ("Impact", "T1486", "Encrypt systems for ransom", None, False),
     ]),
    ("exploit_public_app", "Exploiting unpatched internet-facing software",
     "A known, already-exploited vulnerability in an internet-facing system gives the attacker a way in.", [
         ("Reconnaissance", "T1046", "Identify software versions from outside",
          lambda f: f.code in ("known_cves",) or f.code.endswith(("_eol", "_eol_old", "_outdated")) or _kev(f), True),
         ("Initial access", "T1190", "Run a public exploit for an actively exploited flaw", _kev, True),
         ("Persistence", "T1505", "Install a web shell or back door", None, False),
         ("Exfiltration", "T1041", "Steal data", None, False),
     ]),
    ("exposed_data_store", "Direct access to an exposed database or admin service",
     "A database, Docker or industrial control interface reachable from the internet can be read or controlled directly.", [
         ("Reconnaissance", "T1046", "Find the open service", _code("db_exposed", "docker_api_exposed", "ics_exposed", "ftp_exposed"), True),
         ("Initial access", "T1190", "Connect without (or with weak) authentication", _code("db_exposed", "docker_api_exposed", "ics_exposed"), False),
         ("Collection", "T1005", "Copy data or change settings", None, False),
     ]),
    ("web_session_theft", "Stealing customer sessions on the website",
     "Weak web protections let an attacker inject script or intercept traffic and take over logged-in sessions.", [
         ("Initial access", "T1189", "Inject script through a vulnerable library or missing content policy",
          lambda f: f.code.endswith(("_vulnerable", "_vulnerable_old")) or f.code == "csp_missing", True),
         ("Credential access", "T1539", "Steal session cookies", _code("session_cookie_not_httponly", "cookie_not_secure"), True),
         ("Collection", "T1557", "Intercept traffic over weak encryption", _code("tls_", "cert_", "hsts_missing"), False),
     ]),
    ("subdomain_takeover", "Taking over a forgotten subdomain",
     "A DNS record pointing at a deleted cloud resource lets an attacker host their own content on the company's domain.", [
         ("Resource development", "T1584.001", "Claim the abandoned cloud resource", _code("dangling_cname"), True),
         ("Initial access", "T1566", "Host phishing pages on a trusted company address", _code("dangling_cname"), True),
     ]),
    ("already_compromised", "Attacker already inside",
     "Company systems are already talking to botnets or serving malware, so an attacker may already have a foothold.", [
         ("Command and control", "T1071", "Infected system contacts attacker servers", _code("botnet_c2", "spamhaus_drop", "attack_source"), True),
         ("Execution", "T1608.001", "Malware is hosted on company systems", _code("malware_hosting"), False),
     ]),
]
EXTRA_T = {"T1505": "Server Software Component (web shell)", "T1041": "Exfiltration Over C2 Channel",
           "T1005": "Data from Local System"}


def paths(findings: list[Finding]) -> list[dict]:
    open_findings = [f for f in findings if f.status == "open"]
    out = []
    for pid, name, impact, steps in PATHS:
        rows, required_ok, entry = [], True, False
        for i, (stage, tech, text, test, required) in enumerate(steps):
            hits = [f for f in open_findings if test(f)] if test else []
            state = "evidence" if hits else ("assumed" if test is None else "not_seen")
            if required and not hits:
                required_ok = False
            if i == 0 and hits or (required and hits):
                entry = True
            rows.append({"stage": stage, "technique": {"id": tech, "name": T.get(tech) or EXTRA_T.get(tech, tech),
                                                       "url": f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/"},
                         "step": text, "state": state,
                         "evidence": [{"id": f.id, "title": f.title, "asset": f.asset_value, "severity": f.severity}
                                      for f in hits[:5]]})
        if not entry:
            continue
        seen = sum(r["state"] == "evidence" for r in rows)
        checkable = sum(r["state"] != "assumed" for r in rows)
        status = "open" if required_ok and seen == checkable else "partly_open" if required_ok else "entry_point"
        out.append({"id": pid, "name": name, "impact": impact, "status": status, "steps": rows,
                    "evidence_steps": seen, "checkable_steps": checkable})
    order = {"open": 0, "partly_open": 1, "entry_point": 2}
    return sorted(out, key=lambda p: (order[p["status"]], -p["evidence_steps"]))


@router.get("/entities/{entity_id}/attack-paths")
def entity_paths(entity_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> list[dict]:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    return paths(session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open")).all())
