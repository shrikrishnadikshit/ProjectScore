"""Benchmarking: how a company's score compares with others in its industry and across the platform.

Peers are all companies rated on the platform, whoever added them. Only aggregates are returned, and only
when a group has at least MIN_GROUP companies, so no single peer's score can be inferred.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Entity, Score, User

router = APIRouter(prefix="/api")
MIN_GROUP = 5

INDUSTRIES = [
    "Banking", "NBFC and fintech", "Insurance", "Capital markets", "Healthcare and pharma", "IT and software",
    "IT services and BPO", "Manufacturing", "Retail and e-commerce", "Telecom", "Energy and utilities",
    "Government and public sector", "Education", "Media and entertainment", "Logistics and transport",
    "Hospitality and travel", "Real estate and construction", "Professional services", "Other",
]


def latest_scores(session: Session) -> dict[int, tuple[int, str | None]]:
    """entity_id -> (latest overall score, industry)."""
    newest = (select(Score.entity_id, func.max(Score.id).label("sid")).group_by(Score.entity_id).subquery())
    rows = session.execute(select(Score.entity_id, Score.overall, Entity.industry)
                           .join(newest, Score.id == newest.c.sid)
                           .join(Entity, Entity.id == Score.entity_id)).all()
    return {eid: (overall, industry) for eid, overall, industry in rows}


def _group(score: int, others: list[int]) -> dict:
    n = len(others) + 1
    if n < MIN_GROUP:
        return {"count": n, "median": None, "percentile": None, "min_group": MIN_GROUP}
    allv = sorted(others + [score])
    median = allv[len(allv) // 2] if n % 2 else round((allv[n // 2 - 1] + allv[n // 2]) / 2)
    below = sum(v < score for v in others)
    return {"count": n, "median": median, "percentile": round(100 * below / (n - 1)), "min_group": MIN_GROUP}


def benchmark_for(session: Session, entity_id: int) -> dict | None:
    scores = latest_scores(session)
    if entity_id not in scores:
        return None
    score, industry = scores[entity_id]
    others = [(s, ind) for eid, (s, ind) in scores.items() if eid != entity_id]
    out = {"score": score, "industry": industry, "platform": _group(score, [s for s, _ in others])}
    out["industry_group"] = _group(score, [s for s, ind in others if ind and ind == industry]) if industry else None
    return out


@router.get("/industries")
def industries() -> list[str]:
    return INDUSTRIES


@router.get("/entities/{entity_id}/benchmark")
def entity_benchmark(entity_id: int, user: User = Depends(auth.current_user),
                     session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    return benchmark_for(session, entity_id) or {}


class IndustryIn(BaseModel):
    industry: str | None


@router.patch("/entities/{entity_id}/industry")
def set_industry(entity_id: int, body: IndustryIn, user: User = Depends(auth.require_admin),
                 session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    item = _portfolio_item(session, user, entity_id)
    if body.industry is not None and body.industry not in INDUSTRIES:
        raise HTTPException(422, "choose an industry from the list")
    item.entity.industry = body.industry
    session.commit()
    return {"industry": item.entity.industry}
