"""Vendor risk policy: an organisation's minimum requirements per vendor tier, and who breaks them.

For example: Tier 1 (critical) vendors must score at least 700, have no critical issues and no top-priority
issues, keep ransomware susceptibility below 0.5, hold a current certificate and host nothing in high-risk
countries. Breaches are listed on the Policy page so the team knows which vendors to chase first.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .assets import HIGH_RISK_COUNTRIES, prioritise
from .certificates import status as cert_status
from .models import AssetProfile, Finding, PortfolioItem, RiskPolicy, Score, User, VendorCertificate
from .ransomware import susceptibility

router = APIRouter(prefix="/api")

RULE_KEYS = {
    "min_score": (int, "Minimum rating"),
    "max_critical": (int, "Most critical issues allowed"),
    "max_priority1": (int, "Most top-priority issues allowed"),
    "max_ransomware": (float, "Highest ransomware susceptibility allowed"),
    "require_certificate": (bool, "Must have a current ISO 27001, SOC 2 Type II or PCI DSS certificate"),
    "no_high_risk_hosting": (bool, "No systems hosted in high-risk countries"),
    "max_days_since_scan": (int, "Rating must be newer than this many days"),
}
DEFAULT_RULES = {
    "1": {"min_score": 700, "max_critical": 0, "max_priority1": 0, "max_ransomware": 0.5,
          "require_certificate": True, "no_high_risk_hosting": True, "max_days_since_scan": 14},
    "2": {"min_score": 620, "max_critical": 0, "max_priority1": 3, "max_ransomware": 0.7,
          "require_certificate": False, "no_high_risk_hosting": True, "max_days_since_scan": 30},
    "3": {"min_score": 550, "max_critical": 2, "max_priority1": None, "max_ransomware": None,
          "require_certificate": False, "no_high_risk_hosting": False, "max_days_since_scan": 60},
}
CERT_KINDS = ("iso27001", "soc2_type2", "pci_dss")


def rules_for(session: Session, org_id: int) -> dict:
    row = session.scalars(select(RiskPolicy).where(RiskPolicy.org_id == org_id)).first()
    return row.rules if row and row.rules else DEFAULT_RULES


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def evaluate(rules: dict, *, score: Score | None, findings: list[Finding], profiles: list[AssetProfile],
             certs: list[VendorCertificate], industry: str | None, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    out = []

    def breach(key, detail):
        out.append({"rule": key, "label": RULE_KEYS[key][1], "detail": detail})

    if score is None:
        return [{"rule": "unrated", "label": "Not rated yet", "detail": "Run a first scan to check this vendor."}]
    if rules.get("min_score") is not None and score.overall < rules["min_score"]:
        breach("min_score", f"Rated {score.overall}, below {rules['min_score']}")
    crit = sum(f.severity == "critical" for f in findings)
    if rules.get("max_critical") is not None and crit > rules["max_critical"]:
        breach("max_critical", f"{crit} critical issue(s); allowed {rules['max_critical']}")
    if rules.get("max_priority1") is not None:
        vals = {p.asset: p.value for p in profiles}
        p1 = sum(p["priority"] == 1 for p in prioritise(findings, vals))
        if p1 > rules["max_priority1"]:
            breach("max_priority1", f"{p1} top-priority issue(s); allowed {rules['max_priority1']}")
    if rules.get("max_ransomware") is not None:
        rsi = susceptibility(findings, industry)["index"]
        if rsi > rules["max_ransomware"]:
            breach("max_ransomware", f"Ransomware susceptibility {rsi:.2f}; allowed {rules['max_ransomware']:.2f}")
    if rules.get("require_certificate"):
        if not any(c.kind in CERT_KINDS and cert_status(c) != "expired" for c in certs):
            breach("require_certificate", "No current certificate on record")
    if rules.get("no_high_risk_hosting"):
        bad = sorted({p.country for p in profiles if p.country in HIGH_RISK_COUNTRIES})
        if bad:
            breach("no_high_risk_hosting", "Systems hosted in " + ", ".join(HIGH_RISK_COUNTRIES[c] for c in bad))
    if rules.get("max_days_since_scan") is not None:
        age = (now - _aware(score.created_at)).days
        if age > rules["max_days_since_scan"]:
            breach("max_days_since_scan", f"Last rated {age} days ago")
    return out


class PolicyIn(BaseModel):
    rules: dict[str, dict]

    @field_validator("rules")
    @classmethod
    def _rules(cls, v):
        clean = {}
        for tier in ("1", "2", "3"):
            r = v.get(tier) or {}
            clean[tier] = {}
            for key, (typ, _label) in RULE_KEYS.items():
                val = r.get(key)
                if val in (None, ""):
                    clean[tier][key] = False if typ is bool else None
                    continue
                try:
                    val = bool(val) if typ is bool else typ(val)
                except (TypeError, ValueError):
                    raise ValueError(f"{key} must be a {typ.__name__}")
                if key == "min_score" and not 250 <= val <= 900:
                    raise ValueError("the minimum rating must be between 250 and 900")
                if key == "max_ransomware" and not 0 <= val <= 1:
                    raise ValueError("ransomware susceptibility is between 0 and 1")
                if typ is int and key != "min_score" and val < 0:
                    raise ValueError(f"{key} cannot be negative")
                clean[tier][key] = val
        return clean


@router.get("/policy")
def get_policy(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    return {"rules": rules_for(session, user.org_id), "labels": {k: v[1] for k, v in RULE_KEYS.items()},
            "is_default": session.scalars(select(RiskPolicy).where(RiskPolicy.org_id == user.org_id)).first() is None}


@router.put("/policy")
def set_policy(body: PolicyIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    row = session.scalars(select(RiskPolicy).where(RiskPolicy.org_id == user.org_id)).first() or RiskPolicy(org_id=user.org_id)
    row.rules, row.updated_at = body.rules, datetime.now(timezone.utc)
    session.add(row)
    session.commit()
    return get_policy(user, session)


@router.get("/policy/compliance")
def compliance(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    rules = rules_for(session, user.org_id)
    items = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id)).all()
    ids = [i.entity_id for i in items]
    findings: dict[int, list] = {i: [] for i in ids}
    for f in session.scalars(select(Finding).where(Finding.entity_id.in_(ids), Finding.status == "open")):
        findings[f.entity_id].append(f)
    profiles: dict[int, list] = {i: [] for i in ids}
    for p in session.scalars(select(AssetProfile).where(AssetProfile.entity_id.in_(ids))):
        profiles[p.entity_id].append(p)
    certs: dict[int, list] = {i: [] for i in ids}
    for c in session.scalars(select(VendorCertificate).where(VendorCertificate.org_id == user.org_id)):
        certs.setdefault(c.entity_id, []).append(c)
    rows = []
    for i in items:
        latest = session.scalars(select(Score).where(Score.entity_id == i.entity_id)
                                 .order_by(Score.created_at.desc(), Score.id.desc())).first()
        breaches = evaluate(rules.get(str(i.tier), {}), score=latest, findings=findings[i.entity_id],
                            profiles=profiles[i.entity_id], certs=certs.get(i.entity_id, []), industry=i.entity.industry)
        rows.append({"entity_id": i.entity_id, "name": i.entity.name, "tier": i.tier,
                     "score": latest.overall if latest else None, "grade": latest.grade if latest else None,
                     "compliant": not breaches, "breaches": breaches})
    rows.sort(key=lambda r: (r["compliant"], r["tier"], -len(r["breaches"]), r["name"].lower()))
    return {"companies": rows, "compliant": sum(r["compliant"] for r in rows), "total": len(rows)}
