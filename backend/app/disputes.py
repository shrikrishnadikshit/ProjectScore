"""Finding disputes (BRS 7.1 fairness and 7.5 dispute management).

Signed-in users dispute a specific finding on a company in their portfolio. Rated companies without an
account use the public form on the scanner page. The platform owner reviews both. Accepting a dispute
marks the finding as a false positive, keeps it from reappearing, and recalculates the score at once.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Dispute, Entity, Finding, PortfolioItem, Score, User
from .optout import OptOutIn, limiter, public_daily, require_owner
from .scoring import ScoringFinding, compute_score

router = APIRouter(prefix="/api")


def suppressed_keys(session: Session, entity_id: int) -> set[tuple[str, str]]:
    rows = session.execute(select(Dispute.code, Dispute.asset_value).where(
        Dispute.entity_id == entity_id, Dispute.status == "accepted", Dispute.code.is_not(None))).all()
    return {(c, a) for c, a in rows}


def rescore(session: Session, entity: Entity) -> Score | None:
    """Recalculate from stored findings using the coverage of the latest scan (no new scan)."""
    latest = session.scalars(select(Score).where(Score.entity_id == entity.id)
                             .order_by(Score.created_at.desc(), Score.id.desc())).first()
    if latest is None:
        return None
    coverage = {k: v["assets"] for k, v in (latest.factors or {}).items()}
    findings = session.scalars(select(Finding).where(Finding.entity_id == entity.id)).all()
    result = compute_score(
        [ScoringFinding(risk_factor=f.risk_factor, severity=f.severity, asset_value=f.asset_value, code=f.code,
                        detection_confidence=f.detection_confidence, status=f.status, last_seen=f.last_seen,
                        evidence=f.evidence or {}) for f in findings], coverage)
    result["trace"]["coverage"] = result["coverage"]
    result["trace"]["reason"] = "recalculated after a dispute decision"
    score = Score(entity_id=entity.id, overall=result["overall"], grade=result["grade"],
                  model_version=result["model_version"], factors=result["factors"], trace=result["trace"])
    session.add(score)
    session.commit()
    return score


class DisputeIn(BaseModel):
    reason: str

    @field_validator("reason")
    @classmethod
    def _reason(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 10:
            raise ValueError("please explain why the finding is wrong (at least 10 characters)")
        return v[:4000]


def _out(session: Session, d: Dispute) -> dict:
    finding = session.get(Finding, d.finding_id) if d.finding_id else None
    entity = session.get(Entity, d.entity_id) if d.entity_id else None
    submitter = session.get(User, d.submitted_by) if d.submitted_by else None
    return {"id": d.id, "status": d.status, "reason": d.reason, "reviewer_note": d.reviewer_note,
            "created_at": d.created_at.isoformat(), "decided_at": d.decided_at.isoformat() if d.decided_at else None,
            "entity": {"id": entity.id, "name": entity.name, "domain": entity.primary_domain} if entity else None,
            "domain": d.domain or (entity.primary_domain if entity else None),
            "finding": {"id": finding.id, "title": finding.title, "code": finding.code, "severity": finding.severity,
                        "asset": finding.asset_value, "status": finding.status} if finding else None,
            "submitted_by": submitter.email if submitter else d.contact_email,
            "organisation": submitter.org.name if submitter else "Public form"}


@router.post("/findings/{finding_id}/disputes", status_code=201)
def dispute_finding(finding_id: int, body: DisputeIn, user: User = Depends(auth.current_user),
                    session: Session = Depends(db.get_session)) -> dict:
    finding = session.get(Finding, finding_id)
    in_portfolio = finding and session.scalars(select(PortfolioItem).where(
        PortfolioItem.org_id == user.org_id, PortfolioItem.entity_id == finding.entity_id)).first()
    if not in_portfolio:
        raise HTTPException(404, "finding not found")
    if session.scalars(select(Dispute).where(Dispute.finding_id == finding_id, Dispute.status == "pending")).first():
        raise HTTPException(409, "this finding already has a dispute under review")
    d = Dispute(entity_id=finding.entity_id, finding_id=finding.id, code=finding.code, asset_value=finding.asset_value,
                submitted_by=user.id, reason=body.reason)
    session.add(d)
    session.commit()
    return _out(session, d)


class PublicDisputeIn(OptOutIn):
    reason: str


@router.post("/public/disputes", status_code=202)
def public_dispute(body: PublicDisputeIn, request: Request, session: Session = Depends(db.get_session)) -> dict:
    if body.website:
        return {"status": "received"}
    if not body.reason or len(body.reason.strip()) < 10:
        raise HTTPException(422, "please describe what is wrong (at least 10 characters)")
    client = request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0]
    if not limiter.allow("dispute:" + client.strip()) or not public_daily.allow("all"):
        raise HTTPException(429, "too many requests; please try again later")
    entity = session.scalars(select(Entity).where(Entity.primary_domain == body.domain)).first()
    session.add(Dispute(entity_id=entity.id if entity else None, domain=body.domain, contact_email=body.contact_email,
                        reason=(f"[{body.organisation}] " if body.organisation else "") + body.reason.strip()[:3900]))
    session.commit()
    return {"status": "received"}


@router.get("/entities/{entity_id}/disputes")
def entity_disputes(entity_id: int, user: User = Depends(auth.current_user),
                    session: Session = Depends(db.get_session)) -> list[dict]:
    if not session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id,
                                                       PortfolioItem.entity_id == entity_id)).first():
        raise HTTPException(404, "entity not found")
    rows = session.scalars(select(Dispute).where(Dispute.entity_id == entity_id, Dispute.finding_id.is_not(None))
                           .order_by(Dispute.created_at.desc())).all()
    return [{"id": d.id, "finding_id": d.finding_id, "status": d.status, "reviewer_note": d.reviewer_note} for d in rows]


@router.get("/disputes")
def list_disputes(_: User = Depends(require_owner), session: Session = Depends(db.get_session)) -> list[dict]:
    rows = session.scalars(select(Dispute).order_by(Dispute.status != "pending", Dispute.created_at.desc())).all()
    return [_out(session, d) for d in rows]


class DecisionIn(BaseModel):
    status: str
    note: str | None = None


@router.post("/disputes/{dispute_id}")
def decide_dispute(dispute_id: int, body: DecisionIn, _: User = Depends(require_owner),
                   session: Session = Depends(db.get_session)) -> dict:
    if body.status not in ("accepted", "rejected"):
        raise HTTPException(422, "status must be accepted or rejected")
    d = session.get(Dispute, dispute_id)
    if d is None:
        raise HTTPException(404, "dispute not found")
    d.status, d.reviewer_note, d.decided_at = body.status, (body.note or "").strip()[:2000] or None, datetime.now(timezone.utc)
    finding = session.get(Finding, d.finding_id) if d.finding_id else None
    if finding:
        if body.status == "accepted":
            finding.status = "false_positive"
        elif finding.status == "false_positive":
            finding.status = "open"
    session.commit()
    if finding:
        rescore(session, session.get(Entity, finding.entity_id))
    return _out(session, d)
