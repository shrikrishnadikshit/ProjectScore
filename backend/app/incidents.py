"""Incident log for back-testing (BRS 7.3 calibration).

The platform owner records real incidents at rated companies (from news, regulators or the companies
themselves). Each record keeps the last score before the incident, and /api/backtest compares the scores
of companies that had incidents with those that did not.
"""

from datetime import datetime, timezone
from statistics import mean

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db
from .benchmark import latest_scores
from .models import Entity, Incident, Score, User
from .optout import require_owner

router = APIRouter(prefix="/api")
KINDS = ("breach", "ransomware", "outage", "fraud", "other")


class IncidentIn(BaseModel):
    occurred_on: str
    kind: str
    description: str
    source_url: str | None = None

    @field_validator("kind")
    @classmethod
    def _kind(cls, v):
        if v not in KINDS:
            raise ValueError(f"kind must be one of {', '.join(KINDS)}")
        return v

    @field_validator("description")
    @classmethod
    def _desc(cls, v):
        v = v.strip()
        if len(v) < 5:
            raise ValueError("describe the incident")
        return v[:2000]


def _out(i: Incident) -> dict:
    return {"id": i.id, "entity_id": i.entity_id, "occurred_on": i.occurred_on.date().isoformat(), "kind": i.kind,
            "description": i.description, "source_url": i.source_url, "score_before": i.score_before}


@router.post("/entities/{entity_id}/incidents", status_code=201)
def record_incident(entity_id: int, body: IncidentIn, user: User = Depends(require_owner),
                    session: Session = Depends(db.get_session)) -> dict:
    if session.get(Entity, entity_id) is None:
        raise HTTPException(404, "entity not found")
    try:
        when = datetime.fromisoformat(body.occurred_on).replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(422, "occurred_on must be a date like 2026-11-15")
    before = session.scalars(select(Score).where(Score.entity_id == entity_id, Score.created_at <= when)
                             .order_by(Score.created_at.desc())).first()
    inc = Incident(entity_id=entity_id, occurred_on=when, kind=body.kind, description=body.description,
                   source_url=(body.source_url or "").strip()[:1000] or None,
                   score_before=before.overall if before else None, recorded_by=user.id)
    session.add(inc)
    session.commit()
    return _out(inc)


@router.get("/entities/{entity_id}/incidents")
def list_incidents(entity_id: int, _: User = Depends(require_owner), session: Session = Depends(db.get_session)) -> list[dict]:
    rows = session.scalars(select(Incident).where(Incident.entity_id == entity_id).order_by(Incident.occurred_on.desc())).all()
    return [_out(i) for i in rows]


@router.get("/backtest")
def backtest(_: User = Depends(require_owner), session: Session = Depends(db.get_session)) -> dict:
    incidents = session.scalars(select(Incident)).all()
    hit = {i.entity_id for i in incidents}
    with_scores = [i.score_before for i in incidents if i.score_before is not None]
    clean = [s for eid, (s, _) in latest_scores(session).items() if eid not in hit]
    return {"incidents": len(incidents), "companies_with_incidents": len(hit),
            "mean_score_before_incident": round(mean(with_scores)) if with_scores else None,
            "mean_score_no_incident": round(mean(clean)) if clean else None,
            "note": "Meaningful once there are dozens of incidents; until then treat as anecdotal."}
