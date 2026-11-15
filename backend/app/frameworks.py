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
        "Anti-phishing": "Anti-phishing",
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
    "brand": {"nist_csf": ["DE.CM-01"], "iso27001": ["A.5.7"], "rbi": ["Anti-phishing"],
              "sebi": ["Detect: continuous monitoring"]},
    "breach_history": {"nist_csf": ["RS.MA-01"], "iso27001": ["A.5.26"], "cert_in": ["Incident reporting"],
                       "rbi": ["Incident response and management"], "sebi": ["Respond: incident management"]},
}


# ---------- Global frameworks and regulations ----------
# (key, name, region, {control id: title}, {risk factor: [control ids]})
GLOBAL = [
    ("cis_v8", "CIS Controls v8", "global", {
        "CIS 3": "Data protection (including encryption in transit)",
        "CIS 4": "Secure configuration of enterprise assets and software",
        "CIS 7": "Continuous vulnerability management",
        "CIS 9": "Email and web browser protections",
        "CIS 10": "Malware defenses",
        "CIS 12": "Network infrastructure management",
        "CIS 13": "Network monitoring and defense",
        "CIS 15": "Service provider management",
        "CIS 17": "Incident response management",
    }, {"email_security": ["CIS 9"], "tls": ["CIS 3"], "web_security": ["CIS 4", "CIS 9"], "dns_health": ["CIS 12"],
        "vulnerability": ["CIS 7"], "network_exposure": ["CIS 4", "CIS 12"], "compromise": ["CIS 10", "CIS 13", "CIS 17"],
        "brand": ["CIS 9", "CIS 13"], "breach_history": ["CIS 17"]}),
    ("soc2", "SOC 2 Trust Services Criteria", "global", {
        "CC6.1": "Logical access security over protected information assets",
        "CC6.6": "Boundary protection against threats from outside the system",
        "CC6.7": "Protection of information during transmission",
        "CC6.8": "Prevention and detection of malicious software",
        "CC7.1": "Detection of configuration changes and new vulnerabilities",
        "CC7.2": "Monitoring of system components for anomalies",
        "CC7.4": "Response to identified security incidents",
        "CC9.2": "Assessment and management of vendor and business partner risk",
    }, {"email_security": ["CC6.6"], "tls": ["CC6.7"], "web_security": ["CC6.1", "CC7.1"], "dns_health": ["CC6.6"],
        "vulnerability": ["CC7.1"], "network_exposure": ["CC6.1", "CC6.6"], "compromise": ["CC6.8", "CC7.2", "CC7.4"],
        "brand": ["CC7.2"], "breach_history": ["CC7.4"]}),
    ("pci_dss", "PCI DSS v4.0", "global", {
        "Req 1": "Install and maintain network security controls",
        "Req 2": "Apply secure configurations to all system components",
        "Req 4": "Protect cardholder data with strong cryptography during transmission",
        "Req 5": "Protect all systems and networks from malicious software",
        "Req 6": "Develop and maintain secure systems and software",
        "Req 11": "Test security of systems and networks regularly",
        "Req 12.8": "Manage risk from third-party service providers",
        "Req 12.10": "Respond immediately to suspected and confirmed incidents",
    }, {"email_security": ["Req 5"], "tls": ["Req 4"], "web_security": ["Req 6", "Req 2"], "dns_health": ["Req 2"],
        "vulnerability": ["Req 6", "Req 11"], "network_exposure": ["Req 1", "Req 11"], "compromise": ["Req 5", "Req 12.10"],
        "brand": ["Req 5"], "breach_history": ["Req 12.10"]}),
    ("nis2", "EU NIS2 Directive (2022/2555), Art. 21 and 23", "eu", {
        "Art. 21(2)(a)": "Risk analysis and information system security policies",
        "Art. 21(2)(b)": "Incident handling",
        "Art. 21(2)(d)": "Supply chain security",
        "Art. 21(2)(e)": "Security in acquisition, development and maintenance, including vulnerability handling",
        "Art. 21(2)(g)": "Basic cyber hygiene practices and cybersecurity training",
        "Art. 21(2)(h)": "Cryptography and, where appropriate, encryption",
        "Art. 23": "Reporting of significant incidents (early warning within 24 hours)",
    }, {"email_security": ["Art. 21(2)(g)"], "tls": ["Art. 21(2)(h)"], "web_security": ["Art. 21(2)(e)", "Art. 21(2)(g)"],
        "dns_health": ["Art. 21(2)(g)"], "vulnerability": ["Art. 21(2)(e)", "Art. 21(2)(a)"],
        "network_exposure": ["Art. 21(2)(a)", "Art. 21(2)(g)"], "compromise": ["Art. 21(2)(b)", "Art. 23"],
        "brand": ["Art. 21(2)(g)"], "breach_history": ["Art. 21(2)(b)", "Art. 23"]}),
    ("dora", "EU DORA (2022/2554)", "eu", {
        "Art. 8": "Identification of ICT risks, assets and dependencies",
        "Art. 9": "Protection and prevention, including encryption and patching",
        "Art. 10": "Detection of anomalous activities",
        "Art. 17-19": "ICT-related incident management, classification and reporting",
        "Art. 24-25": "Digital operational resilience testing, including vulnerability scans",
        "Art. 28": "Management of ICT third-party risk",
    }, {"email_security": ["Art. 9"], "tls": ["Art. 9"], "web_security": ["Art. 9"], "dns_health": ["Art. 8", "Art. 9"],
        "vulnerability": ["Art. 9", "Art. 24-25"], "network_exposure": ["Art. 8", "Art. 9"],
        "compromise": ["Art. 10", "Art. 17-19"], "brand": ["Art. 10"], "breach_history": ["Art. 17-19"]}),
    ("gdpr", "EU / UK GDPR", "eu", {
        "Art. 28": "Processors must give sufficient guarantees of appropriate security",
        "Art. 32": "Security of processing, including encryption and regular testing",
        "Art. 33": "Notify the supervisory authority of a personal data breach within 72 hours",
    }, {"email_security": ["Art. 32"], "tls": ["Art. 32"], "web_security": ["Art. 32"], "dns_health": ["Art. 32"],
        "vulnerability": ["Art. 32"], "network_exposure": ["Art. 32"], "compromise": ["Art. 32", "Art. 33"],
        "breach_history": ["Art. 33"]}),
    ("uk_ce", "UK Cyber Essentials", "uk", {
        "Firewalls": "Boundary firewalls and internet gateways",
        "Secure configuration": "Secure configuration",
        "Security update management": "Security update management (critical patches within 14 days)",
        "User access control": "User access control",
        "Malware protection": "Malware protection",
    }, {"email_security": ["Secure configuration"], "tls": ["Secure configuration"], "web_security": ["Secure configuration"],
        "dns_health": ["Secure configuration"], "vulnerability": ["Security update management"],
        "network_exposure": ["Firewalls", "User access control"], "compromise": ["Malware protection"]}),
    ("hipaa", "US HIPAA Security Rule (45 CFR 164)", "us", {
        "164.308(a)(1)": "Security management process: risk analysis and risk management",
        "164.308(a)(5)": "Security awareness, including protection from malicious software",
        "164.308(a)(6)": "Security incident procedures",
        "164.308(b)": "Business associate contracts and assurances",
        "164.312(e)(1)": "Transmission security",
    }, {"email_security": ["164.308(a)(5)"], "tls": ["164.312(e)(1)"], "web_security": ["164.308(a)(1)"],
        "dns_health": ["164.308(a)(1)"], "vulnerability": ["164.308(a)(1)"], "network_exposure": ["164.308(a)(1)"],
        "compromise": ["164.308(a)(5)", "164.308(a)(6)"], "brand": ["164.308(a)(5)"], "breach_history": ["164.308(a)(6)"]}),
    ("nydfs", "US NYDFS 23 NYCRR 500", "us", {
        "500.5": "Vulnerability management, including penetration testing and scans",
        "500.7": "Access privileges and management",
        "500.11": "Third-party service provider security policy",
        "500.15": "Encryption of nonpublic information in transit and at rest",
        "500.16": "Incident response and business continuity",
        "500.17": "Notice of cybersecurity events within 72 hours",
    }, {"email_security": ["500.7"], "tls": ["500.15"], "web_security": ["500.5"], "dns_health": ["500.5"],
        "vulnerability": ["500.5"], "network_exposure": ["500.5", "500.7"], "compromise": ["500.16", "500.17"],
        "breach_history": ["500.17"]}),
    ("sec", "US SEC cybersecurity disclosure rules (2023)", "us", {
        "S-K Item 106": "Processes to assess and manage cybersecurity risk, including third-party service providers",
        "8-K Item 1.05": "Disclose material cybersecurity incidents within four business days",
    }, {"email_security": ["S-K Item 106"], "tls": ["S-K Item 106"], "web_security": ["S-K Item 106"],
        "dns_health": ["S-K Item 106"], "vulnerability": ["S-K Item 106"], "network_exposure": ["S-K Item 106"],
        "compromise": ["8-K Item 1.05"], "breach_history": ["8-K Item 1.05"]}),
    ("apra", "Australia APRA CPS 234", "au", {
        "Information security capability": "Maintain an information security capability matching threats",
        "Implementation of controls": "Implement controls to protect information assets",
        "Incident management": "Detect and respond to information security incidents",
        "Testing control effectiveness": "Test the effectiveness of controls, including at third parties",
        "Notification": "Notify APRA of material incidents within 72 hours",
    }, {"email_security": ["Implementation of controls"], "tls": ["Implementation of controls"],
        "web_security": ["Implementation of controls"], "dns_health": ["Implementation of controls"],
        "vulnerability": ["Testing control effectiveness", "Information security capability"],
        "network_exposure": ["Implementation of controls"], "compromise": ["Incident management", "Notification"],
        "brand": ["Information security capability"], "breach_history": ["Incident management"]}),
    ("mas_trm", "Singapore MAS Technology Risk Management Guidelines", "sg", {
        "Third party management": "IT outsourcing and third party management",
        "Secure configuration": "IT service management and secure configuration",
        "Vulnerability management": "Cyber security assessment and vulnerability management",
        "Cryptography": "Cryptography",
        "Cyber security operations": "Cyber security operations and threat monitoring",
        "Incident management": "IT incident management",
    }, {"email_security": ["Secure configuration"], "tls": ["Cryptography"], "web_security": ["Secure configuration"],
        "dns_health": ["Secure configuration"], "vulnerability": ["Vulnerability management"],
        "network_exposure": ["Secure configuration", "Vulnerability management"],
        "compromise": ["Cyber security operations", "Incident management"], "brand": ["Cyber security operations"],
        "breach_history": ["Incident management"]}),
    ("nca_ecc", "Saudi Arabia NCA Essential Cybersecurity Controls", "sa", {
        "Email protection": "Email protection",
        "Networks security management": "Networks security management",
        "Cryptography": "Cryptography",
        "Vulnerabilities management": "Vulnerabilities management",
        "Web application security": "Web application security",
        "Event logs and monitoring": "Cybersecurity event logs and monitoring management",
        "Incident and threat management": "Cybersecurity incident and threat management",
        "Third-party cybersecurity": "Third-party cybersecurity",
    }, {"email_security": ["Email protection"], "tls": ["Cryptography"], "web_security": ["Web application security"],
        "dns_health": ["Networks security management"], "vulnerability": ["Vulnerabilities management"],
        "network_exposure": ["Networks security management"],
        "compromise": ["Event logs and monitoring", "Incident and threat management"],
        "brand": ["Incident and threat management"], "breach_history": ["Incident and threat management"]}),
    ("uae_ia", "UAE Information Assurance Regulation", "ae", {
        "Communications": "Communications and network security",
        "Operations management": "Operations management, including vulnerability and patch management",
        "Information systems acquisition": "Information systems acquisition, development and maintenance",
        "Third party security": "Third party security",
        "Incident management": "Information security incident management",
    }, {"email_security": ["Communications"], "tls": ["Communications"], "web_security": ["Information systems acquisition"],
        "dns_health": ["Communications"], "vulnerability": ["Operations management"], "network_exposure": ["Communications"],
        "compromise": ["Incident management"], "breach_history": ["Incident management"]}),
]
REGIONS = {"global": "Global", "india": "India", "eu": "European Union", "uk": "United Kingdom", "us": "United States",
           "au": "Australia", "sg": "Singapore", "sa": "Saudi Arabia", "ae": "United Arab Emirates"}
FRAMEWORK_REGION = {"nist_csf": "global", "iso27001": "global", "cert_in": "india", "rbi": "india", "sebi": "india"}
for _key, _name, _region, _controls, _factors in GLOBAL:
    FRAMEWORKS[_key] = {"name": _name, "controls": _controls}
    FRAMEWORK_REGION[_key] = _region
    for _factor, _ids in _factors.items():
        FACTOR_CONTROLS.setdefault(_factor, {})[_key] = _ids
# Country (ISO code) -> regions whose frameworks are most relevant there by default.
EU = {"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT",
      "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO"}


def regions_for(country: str | None) -> list[str]:
    c = (country or "IN").upper()
    extra = {"IN": "india", "GB": "uk", "US": "us", "AU": "au", "SG": "sg", "SA": "sa", "AE": "ae"}.get(c)
    if c in EU:
        extra = "eu"
    out = ["global"] + ([extra] if extra else [])
    if c == "GB":
        out.append("eu")  # UK GDPR mirrors the EU GDPR
    return out

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
        region = FRAMEWORK_REGION.get(fw_key, "global")
        out.append({"key": fw_key, "name": fw["name"], "region": region, "region_name": REGIONS[region],
                    "controls": controls})
    return out


@router.get("/entities/{entity_id}/frameworks")
def entity_frameworks(entity_id: int, user: User = Depends(auth.current_user),
                      session: Session = Depends(db.get_session)) -> list[dict]:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    latest = session.scalars(select(Score).where(Score.entity_id == entity_id)
                             .order_by(Score.created_at.desc(), Score.id.desc())).first()
    findings = session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open")).all()
    from .orgsettings import settings_for

    result = mapping(findings, set((latest.factors or {}).keys()) if latest else set())
    preferred = regions_for(settings_for(session, user.org_id)["country"])
    for fw in result:
        fw["preferred"] = fw["region"] in preferred
    return result
