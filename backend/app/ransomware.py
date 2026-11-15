"""Ransomware susceptibility: how likely a company is to be hit by ransomware, from 0.0 to 1.0.

Ransomware gangs mostly get in the same few ways: exposed remote access (RDP, VPN, SMB), unpatched
internet-facing software (above all vulnerabilities already exploited in the wild), phishing, and stolen
passwords. We look for the outside signs of each, add industry targeting, and combine them with a
logistic curve. Every signal and its weight is shown, so the number can be explained and challenged.
It is a ranking aid for prioritising vendors, not a prediction for any single company.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Entity, Finding, PortfolioItem, User

router = APIRouter(prefix="/api")

BASELINE = -2.4  # about 8% with no signals at all
# (signal id, label, weight, test on an open finding)
SIGNALS = [
    ("remote_access", "Remote desktop or file sharing open to the internet (RDP, SMB, VNC, Telnet)", 1.6,
     lambda f: f.code.split("_exposed")[0] in ("rdp", "smb", "vnc", "telnet", "netbios") and "_exposed" in f.code),
    ("exploited_vuln", "Internet-facing software with vulnerabilities already exploited in the wild (CISA KEV)", 1.5,
     lambda f: f.code in ("kev_exposed", "apache_path_traversal_kev") or (f.evidence or {}).get("kev") is True),
    ("old_software", "Outdated or end-of-life internet-facing software", 0.7,
     lambda f: f.code in ("known_cves", "openssl_heartbleed_risk") or f.code.endswith(("_eol", "_eol_old", "_outdated"))),
    ("exposed_services", "Databases, file transfer or admin interfaces open to the internet", 0.6,
     lambda f: f.code.startswith(("db_exposed", "ftp_exposed", "docker_api_exposed", "ics_exposed", "ai_service_exposed"))),
    ("phishing", "Email can be spoofed (missing or unenforced SPF/DMARC)", 0.5,
     lambda f: f.code in ("spf_missing", "spf_pass_all", "dmarc_missing", "dmarc_monitor_only")),
    ("lookalikes", "Look-alike domains that can send email", 0.2, lambda f: f.code == "lookalike_domain_mail"),
    ("compromised", "Signs of an existing compromise (botnet or malware activity)", 1.2,
     lambda f: f.code in ("botnet_c2", "malware_hosting", "spamhaus_drop") or f.code.startswith("ransomware_leak_")),
    ("leaked_passwords", "Recent data breach or infostealer malware that exposed staff passwords", 0.6,
     lambda f: f.code == "infostealer_employees" and f.severity in ("high", "medium") or f.code.startswith("breach_") and any("password" in c.lower() for c in (f.evidence or {}).get("data_classes", []))),
    ("slow_patching", "Serious issues left unfixed for more than 30 days", 0.5, lambda f: f.code.startswith("slow_patch_")),
]
# Sectors most often hit in public ransomware reporting (e.g. CERT-In, Sophos and Verizon DBIR reports).
INDUSTRY_WEIGHT = {"Healthcare and pharma": 0.5, "Manufacturing": 0.5, "Education": 0.5,
                   "Government and public sector": 0.4, "Energy and utilities": 0.3, "Retail and e-commerce": 0.3,
                   "Logistics and transport": 0.3, "IT services and BPO": 0.3, "Real estate and construction": 0.2,
                   "Professional services": 0.2}


def level(index: float) -> str:
    return "critical" if index >= 0.7 else "high" if index >= 0.5 else "medium" if index >= 0.3 else "low"


def susceptibility(findings: list[Finding], industry: str | None) -> dict:
    open_findings = [f for f in findings if f.status == "open"]
    hits = []
    for sid, label, weight, test in SIGNALS:
        matched = [f for f in open_findings if test(f)]
        if matched:
            hits.append({"id": sid, "label": label, "weight": weight, "count": len(matched),
                         "examples": sorted({f.asset_value for f in matched})[:3]})
    x = BASELINE + sum(h["weight"] for h in hits)
    if industry in INDUSTRY_WEIGHT:
        hits.append({"id": "industry", "label": f"{industry} is often targeted by ransomware gangs",
                     "weight": INDUSTRY_WEIGHT[industry], "count": 1, "examples": []})
        x += INDUSTRY_WEIGHT[industry]
    index = 1 / (1 + math.exp(-x))
    return {"index": round(index, 2), "level": level(index), "signals": hits,
            "method": "logistic(-2.4 + sum of signal weights); each signal counts once"}


def for_entity(session: Session, entity: Entity) -> dict:
    findings = session.scalars(select(Finding).where(Finding.entity_id == entity.id, Finding.status == "open")).all()
    return susceptibility(findings, entity.industry)


@router.get("/entities/{entity_id}/ransomware")
def entity_ransomware(entity_id: int, user: User = Depends(auth.current_user),
                      session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    item = _portfolio_item(session, user, entity_id)
    return for_entity(session, item.entity)


@router.get("/ransomware")
def portfolio_ransomware(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> list[dict]:
    items = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id)).all()
    ids = [i.entity_id for i in items]
    by_entity: dict[int, list[Finding]] = {i: [] for i in ids}
    for f in session.scalars(select(Finding).where(Finding.entity_id.in_(ids), Finding.status == "open")):
        by_entity[f.entity_id].append(f)
    rows = []
    for i in items:
        r = susceptibility(by_entity[i.entity_id], i.entity.industry)
        rows.append({"entity_id": i.entity_id, "name": i.entity.name, "index": r["index"], "level": r["level"],
                     "top_signal": r["signals"][0]["label"] if r["signals"] else None})
    return sorted(rows, key=lambda r: -r["index"])
