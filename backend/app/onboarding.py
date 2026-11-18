"""Vendor onboarding: intake with business context, inherent-risk tiering, assessment, approval, reassessment.

The intake asks what the vendor will do for you (data it handles, access it gets, how critical it is). That
gives an inherent-risk score and a suggested tier, which decides how deep the assessment goes: which
questionnaire questions, whether certificates are needed, and the minimum rating from your risk policy.
An admin then approves, approves with conditions or rejects, and the vendor is due for reassessment on a
schedule set by its tier.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import (Alert, AssetProfile, Finding, PortfolioItem, Questionnaire, Score, User, VendorCertificate,
                     VendorOnboarding)

router = APIRouter(prefix="/api")

# (key, question, {option: points}); the points add up to the inherent-risk score (0 to 100).
INTAKE = [
    ("data", "What is the most sensitive data the vendor will hold or see?",
     {"none": 0, "internal": 8, "personal": 18, "sensitive_personal": 25, "financial": 25, "health": 25}),
    ("volume", "How many records or people's data?", {"none": 0, "small": 2, "medium": 6, "large": 10}),
    ("access", "What access will the vendor have to your systems?",
     {"none": 0, "read": 6, "write": 12, "admin": 20, "network": 20}),
    ("criticality", "If the vendor failed for a week, how badly would your business be hit?",
     {"low": 0, "medium": 8, "high": 15, "critical": 20}),
    ("hosting", "Does the vendor host or process your data on its own systems?", {"no": 0, "yes": 8}),
    ("offshore", "Is your data processed outside your country?", {"no": 0, "yes": 5}),
    ("ai", "Will the vendor use AI on your data?", {"no": 0, "yes": 5}),
    ("subcontractors", "Does the vendor pass your data to its own suppliers?", {"no": 0, "yes": 4}),
    ("regulated", "Is the service covered by regulation (RBI, SEBI, IRDAI, DPDP Act, GDPR, HIPAA, PCI DSS)?",
     {"no": 0, "yes": 8}),
]
INTAKE_KEYS = {k: opts for k, _, opts in INTAKE}
MAX_POINTS = sum(max(opts.values()) for _, _, opts in INTAKE)
REVIEW_MONTHS = {1: 6, 2: 12, 3: 24}
REQUIREMENTS = {
    1: ["Full security questionnaire", "Current ISO 27001 or SOC 2 certificate", "Meets your tier 1 risk policy",
        "No open critical issues"],
    2: ["Standard security questionnaire", "Meets your tier 2 risk policy"],
    3: ["Security rating meets your tier 3 risk policy"],
}
STAGES = ("intake", "assessment", "review", "approved", "conditional", "rejected")


def inherent(intake: dict) -> tuple[int | None, int | None, str | None]:
    """Score 0-100, suggested tier and level, or Nones while the intake is incomplete."""
    if any(intake.get(k) not in opts for k, opts in INTAKE_KEYS.items()):
        return None, None, None
    score = round(100 * sum(INTAKE_KEYS[k][intake[k]] for k in INTAKE_KEYS) / MAX_POINTS)
    # Some answers alone make a vendor critical, whatever the total.
    if intake["access"] in ("admin", "network") or intake["criticality"] == "critical" or (
            intake["data"] in ("sensitive_personal", "financial", "health") and intake["volume"] == "large"):
        score = max(score, 60)
    level = "critical" if score >= 60 else "high" if score >= 40 else "medium" if score >= 20 else "low"
    tier = 1 if score >= 40 else 2 if score >= 20 else 3
    return score, tier, level


def _months(d: date, months: int) -> date:
    y, m = divmod(d.month - 1 + months, 12)
    return date(d.year + y, m + 1, min(d.day, 28))


def checks(session: Session, ob: VendorOnboarding) -> list[dict]:
    """Assessment gates for the vendor's tier: each is met, not met or pending."""
    from .policy import evaluate, rules_for

    tier = ob.tier or 3
    out = []
    q = session.scalars(select(Questionnaire).where(Questionnaire.org_id == ob.org_id, Questionnaire.entity_id == ob.entity_id)
                        .order_by(Questionnaire.created_at.desc())).first()
    if tier <= 2:
        state = "met" if q and q.status in ("submitted", "reviewed") else "pending" if q else "not_met"
        out.append({"check": "Security questionnaire answered", "state": state,
                    "detail": f"Status: {q.status}" if q else "Not sent yet"})
    if tier == 1:
        certs = session.scalars(select(VendorCertificate).where(VendorCertificate.org_id == ob.org_id,
                                                               VendorCertificate.entity_id == ob.entity_id)).all()
        from .certificates import status as cert_status
        good = [c for c in certs if c.kind in ("iso27001", "soc2_type2", "soc2_type1") and cert_status(c) != "expired"]
        out.append({"check": "Current ISO 27001 or SOC 2 certificate", "state": "met" if good else "not_met",
                    "detail": ", ".join(c.kind for c in good) or "None recorded"})
    latest = session.scalars(select(Score).where(Score.entity_id == ob.entity_id)
                             .order_by(Score.created_at.desc(), Score.id.desc())).first()
    findings = session.scalars(select(Finding).where(Finding.entity_id == ob.entity_id, Finding.status == "open")).all()
    if latest is None:
        out.append({"check": f"Meets your tier {tier} risk policy", "state": "pending", "detail": "Waiting for the first scan"})
    else:
        profiles = session.scalars(select(AssetProfile).where(AssetProfile.entity_id == ob.entity_id)).all()
        certs = session.scalars(select(VendorCertificate).where(VendorCertificate.org_id == ob.org_id,
                                                               VendorCertificate.entity_id == ob.entity_id)).all()
        item = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == ob.org_id,
                                                           PortfolioItem.entity_id == ob.entity_id)).first()
        breaches = evaluate(rules_for(session, ob.org_id).get(str(tier), {}), score=latest, findings=findings,
                            profiles=profiles, certs=certs, industry=item.entity.industry if item else None)
        out.append({"check": f"Meets your tier {tier} risk policy", "state": "not_met" if breaches else "met",
                    "detail": "; ".join(f"{b.get('label')}: {b.get('detail')}" if isinstance(b, dict) else str(b) for b in breaches[:4])
                    or f"Rating {latest.overall} ({latest.grade})"})
    if tier == 1:
        crit = [f for f in findings if f.severity == "critical"]
        out.append({"check": "No open critical issues", "state": "not_met" if crit else "met",
                    "detail": f"{len(crit)} critical" if crit else "None"})
    return out


def _out(session: Session, ob: VendorOnboarding, detail: bool = False) -> dict:
    item = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == ob.org_id,
                                                       PortfolioItem.entity_id == ob.entity_id)).first()
    score, tier, level = inherent(ob.intake or {})
    today = date.today()
    out = {"id": ob.id, "entity_id": ob.entity_id, "name": item.entity.name if item else None,
           "domain": item.entity.primary_domain if item else None, "stage": ob.stage,
           "inherent_score": ob.inherent_score, "level": level, "tier": ob.tier,
           "next_review": ob.next_review.isoformat() if ob.next_review else None,
           "review_due": bool(ob.next_review and ob.next_review <= today),
           "updated_at": ob.updated_at.isoformat() if ob.updated_at else None}
    if detail:
        out["residual"] = residual_for(session, ob)
        out.update({"intake": ob.intake or {}, "decision_note": ob.decision_note, "history": ob.history or [],
                    "requirements": REQUIREMENTS.get(ob.tier or 3, []),
                    "checks": checks(session, ob) if ob.tier else [],
                    "questions": [{"key": k, "text": t, "options": list(opts)} for k, t, opts in INTAKE]})
    return out


def residual_for(session: Session, ob: VendorOnboarding) -> dict | None:
    from .questionnaires import score_answers, selected
    from .workflow import residual

    latest = session.scalars(select(Score).where(Score.entity_id == ob.entity_id)
                             .order_by(Score.created_at.desc(), Score.id.desc())).first()
    q = session.scalars(select(Questionnaire).where(Questionnaire.org_id == ob.org_id, Questionnaire.entity_id == ob.entity_id,
                                                    Questionnaire.status.in_(("submitted", "reviewed")))
                        .order_by(Questionnaire.created_at.desc())).first()
    qscore = score_answers(q.answers or {}, selected(session, q)) if q else None
    sev = [s for (s,) in session.execute(select(Finding.severity).where(Finding.entity_id == ob.entity_id, Finding.status == "open"))]
    return residual(ob.inherent_score, latest.overall if latest else None, qscore, sev.count("critical"), sev.count("high"))


def _own(session: Session, user: User, oid: int) -> VendorOnboarding:
    ob = session.get(VendorOnboarding, oid)
    if ob is None or ob.org_id != user.org_id:
        raise HTTPException(404, "onboarding not found")
    return ob


def _log(ob: VendorOnboarding, user: User, action: str, note: str | None = None) -> None:
    ob.history = (ob.history or []) + [{"at": datetime.now(timezone.utc).isoformat(), "by": user.name or user.email,
                                        "action": action, "note": note}]
    ob.updated_at = datetime.now(timezone.utc)


class StartIn(BaseModel):
    entity_id: int
    intake: dict[str, str] = {}


class IntakeIn(BaseModel):
    intake: dict[str, str]


class ActionIn(BaseModel):
    action: str
    note: str | None = None
    tier: int | None = None


@router.get("/onboarding")
def list_onboarding(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    rows = session.scalars(select(VendorOnboarding).where(VendorOnboarding.org_id == user.org_id)
                           .order_by(VendorOnboarding.updated_at.desc())).all()
    out = [_out(session, r) for r in rows]
    return {"items": out, "stages": STAGES, "due": sum(1 for r in out if r["review_due"])}


@router.post("/onboarding", status_code=201)
def start(body: StartIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, body.entity_id)
    if session.scalars(select(VendorOnboarding).where(VendorOnboarding.org_id == user.org_id,
                                                      VendorOnboarding.entity_id == body.entity_id)).first():
        raise HTTPException(409, "this company is already being onboarded")
    ob = VendorOnboarding(org_id=user.org_id, entity_id=body.entity_id, owner_id=user.id, intake={}, history=[])
    _apply_intake(ob, body.intake)
    _log(ob, user, "started")
    session.add(ob)
    session.commit()
    return _out(session, ob, detail=True)


def _apply_intake(ob: VendorOnboarding, intake: dict) -> None:
    clean = {k: v for k, v in intake.items() if k in INTAKE_KEYS and v in INTAKE_KEYS[k]}
    ob.intake = {**(ob.intake or {}), **clean}
    score, tier, _ = inherent(ob.intake)
    ob.inherent_score, ob.tier = score, tier


@router.get("/onboarding/{oid}")
def get_onboarding(oid: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    return _out(session, _own(session, user, oid), detail=True)


@router.put("/onboarding/{oid}/intake")
def save_intake(oid: int, body: IntakeIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    ob = _own(session, user, oid)
    if ob.stage in ("approved", "conditional", "rejected"):
        raise HTTPException(409, "reopen the onboarding to change the intake")
    _apply_intake(ob, body.intake)
    _log(ob, user, "intake updated")
    session.commit()
    return _out(session, ob, detail=True)


# action -> (allowed from stages, new stage)
ACTIONS = {
    "start_assessment": (("intake",), "assessment"),
    "submit_for_review": (("assessment",), "review"),
    "approve": (("review", "assessment"), "approved"),
    "approve_with_conditions": (("review", "assessment"), "conditional"),
    "reject": (("review", "assessment", "intake"), "rejected"),
    "reopen": (("approved", "conditional", "rejected"), "assessment"),
}


@router.post("/onboarding/{oid}/action")
def act(oid: int, body: ActionIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    ob = _own(session, user, oid)
    if body.action not in ACTIONS:
        raise HTTPException(422, "unknown action")
    allowed, new_stage = ACTIONS[body.action]
    if ob.stage not in allowed:
        raise HTTPException(409, f"cannot {body.action.replace('_', ' ')} from {ob.stage}")
    if body.action == "start_assessment" and ob.tier is None:
        raise HTTPException(422, "answer every intake question first")
    if body.tier is not None:
        if body.tier not in (1, 2, 3):
            raise HTTPException(422, "tier must be 1, 2 or 3")
        ob.tier = body.tier
    note = (body.note or "").strip()[:2000] or None
    if body.action in ("approve_with_conditions", "reject") and not note:
        raise HTTPException(422, "please add a note saying why")
    ob.stage = new_stage
    if body.action.startswith("approve"):
        ob.decision_note = note
        ob.next_review = _months(date.today(), REVIEW_MONTHS[ob.tier or 3])
        item = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == ob.org_id,
                                                           PortfolioItem.entity_id == ob.entity_id)).first()
        if item:
            item.tier = ob.tier or item.tier
    elif body.action == "reject":
        ob.decision_note, ob.next_review = note, None
    _log(ob, user, body.action.replace("_", " "), note)
    session.commit()
    from . import integrations

    integrations.notify_org(session, ob.org_id, f"Vendor onboarding: {_out(session, ob)['name']} is now {new_stage}",
                            note or "", link=f"/onboarding/{ob.id}")
    return _out(session, ob, detail=True)


def review_reminders(session: Session, today: date | None = None) -> int:
    """One alert per vendor whose reassessment date has arrived, sent once for each review date."""
    today = today or date.today()
    due = session.scalars(select(VendorOnboarding).where(VendorOnboarding.next_review <= today,
                                                         VendorOnboarding.stage.in_(("approved", "conditional")))).all()
    sent = 0
    for ob in due:
        marker = ob.next_review.isoformat()
        if any(h.get("action") == "reassessment due" and h.get("note") == marker for h in ob.history or []):
            continue
        sent += 1
        item = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == ob.org_id,
                                                           PortfolioItem.entity_id == ob.entity_id)).first()
        session.add(Alert(org_id=ob.org_id, entity_id=ob.entity_id, kind="reassessment_due", severity="warning",
                          title=f"{item.entity.name if item else 'Vendor'}: reassessment due",
                          detail=f"Tier {ob.tier} vendors are reassessed every {REVIEW_MONTHS.get(ob.tier or 3)} months."))
        ob.history = (ob.history or []) + [{"at": datetime.now(timezone.utc).isoformat(), "by": "ProjectScore",
                                            "action": "reassessment due", "note": marker}]
    session.commit()
    return sent
