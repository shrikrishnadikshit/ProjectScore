"""Indicative mapping of findings to security frameworks and Indian regulations.

Outside-in findings are evidence about a control, not a compliance assessment: a clean result means we
saw no problem from the internet, not that the control is in place. Each risk factor is mapped to the
controls it gives evidence on. Indian frameworks are referenced by section name rather than paragraph
number, because their numbering changes between editions.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Finding, Score, User

router = APIRouter(prefix="/api")

FRAMEWORKS: dict[str, dict] = {
    "nist_csf": {"name": "NIST CSF 2.0", "controls": {
        "ID.RA-01": "Vulnerabilities in assets are identified, validated and recorded",
        "PR.PS-01": "Configuration management practices are established and applied",
        "PR.PS-02": "Software is maintained, replaced and removed commensurate with risk",
        "PR.DS-02": "The confidentiality, integrity and availability of data in transit are protected",
        "PR.IR-01": "Networks and environments are protected from unauthorised logical access and usage",
        "DE.CM-01": "Networks and network services are monitored to find potentially adverse events",
        "RS.MA-01": "The incident response plan is executed once an incident is declared",
    }},
    "iso27001": {"name": "ISO/IEC 27001:2022 Annex A", "controls": {
        "A.5.7": "Threat intelligence",
        "A.5.14": "Information transfer",
        "A.5.26": "Response to information security incidents",
        "A.8.7": "Protection against malware",
        "A.8.8": "Management of technical vulnerabilities",
        "A.8.9": "Configuration management",
        "A.8.20": "Networks security",
        "A.8.21": "Security of network services",
        "A.8.24": "Use of cryptography",
        "A.8.26": "Application security requirements",
    }},
    "cert_in": {"name": "CERT-In Directions (April 2022)", "controls": {
        "Incident reporting": "Report listed cyber incidents to CERT-In within 6 hours of noticing them",
        "Logs and time sync": "Keep ICT system logs for 180 days and synchronise clocks to an authorised NTP source",
    }},
    "rbi": {"name": "RBI Cyber Security Framework (2016)", "controls": {
        "Network management and security": "Network management and security",
        "Secure configuration": "Secure configuration",
        "Application security life cycle": "Application security life cycle",
        "Patch and vulnerability management": "Patch, vulnerability and change management",
        "Secure mail and messaging": "Secure mail and messaging systems",
        "Incident response and management": "Incident response and management",
    }},
    "sebi": {"name": "SEBI CSCRF (2024)", "controls": {
        "Identify: risk assessment": "Identify: risk assessment and vulnerability management",
        "Protect: data security": "Protect: data security, including encryption in transit",
        "Protect: platform security": "Protect: platform security and secure configuration",
        "Protect: network security": "Protect: network security",
        "Detect: continuous monitoring": "Detect: continuous security monitoring",
        "Respond: incident management": "Respond: incident management and reporting",
    }},
}

# Risk factor -> {framework -> controls it gives evidence on}.
FACTOR_CONTROLS: dict[str, dict[str, list[str]]] = {
    "email_security": {"nist_csf": ["PR.PS-01", "PR.DS-02"], "iso27001": ["A.5.14", "A.8.21"],
                       "rbi": ["Secure mail and messaging"], "sebi": ["Protect: platform security"]},
    "tls": {"nist_csf": ["PR.DS-02"], "iso27001": ["A.8.24"], "rbi": ["Secure configuration"],
            "sebi": ["Protect: data security"]},
    "web_security": {"nist_csf": ["PR.PS-01"], "iso27001": ["A.8.9", "A.8.26"],
                     "rbi": ["Application security life cycle"], "sebi": ["Protect: platform security"]},
    "dns_health": {"nist_csf": ["PR.PS-01"], "iso27001": ["A.8.9", "A.8.20"],
                   "rbi": ["Network management and security"], "sebi": ["Protect: network security"]},
    "vulnerability": {"nist_csf": ["ID.RA-01", "PR.PS-02"], "iso27001": ["A.8.8"],
                      "rbi": ["Patch and vulnerability management"], "sebi": ["Identify: risk assessment"]},
    "network_exposure": {"nist_csf": ["PR.IR-01", "PR.PS-01"], "iso27001": ["A.8.20", "A.8.21"],
                         "rbi": ["Network management and security"], "sebi": ["Protect: network security"]},
    "compromise": {"nist_csf": ["DE.CM-01", "RS.MA-01"], "iso27001": ["A.5.7", "A.8.7", "A.5.26"],
                   "cert_in": ["Incident reporting"], "rbi": ["Incident response and management"],
                   "sebi": ["Detect: continuous monitoring", "Respond: incident management"]},
}

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def mapping(findings: list, assessed_factors: set[str]) -> list[dict]:
    """For each framework, each control with its status: issues, no_issues or not_assessed."""
    out = []
    for fw_key, fw in FRAMEWORKS.items():
        controls = []
        for cid, title in fw["controls"].items():
            factors = [f for f, m in FACTOR_CONTROLS.items() if cid in m.get(fw_key, [])]
            if not factors:
                controls.append({"id": cid, "title": title, "status": "out_of_scope", "factors": [], "findings": []})
                continue
            hits = sorted((f for f in findings if f.risk_factor in factors),
                          key=lambda f: SEVERITIES.index(f.severity) if f.severity in SEVERITIES else 9)
            assessed = any(f in assessed_factors for f in factors)
            status = "issues" if hits else ("no_issues" if assessed else "not_assessed")
            controls.append({"id": cid, "title": title, "status": status, "factors": factors,
                             "findings": [{"id": f.id, "title": f.title, "severity": f.severity, "asset": f.asset_value}
                                          for f in hits]})
        out.append({"key": fw_key, "name": fw["name"], "controls": controls})
    return out


@router.get("/entities/{entity_id}/frameworks")
def entity_frameworks(entity_id: int, user: User = Depends(auth.current_user),
                      session: Session = Depends(db.get_session)) -> list[dict]:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    latest = session.scalars(select(Score).where(Score.entity_id == entity_id)
                             .order_by(Score.created_at.desc(), Score.id.desc())).first()
    findings = session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open")).all()
    return mapping(findings, set((latest.factors or {}).keys()) if latest else set())
