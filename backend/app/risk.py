"""Cyber risk in rupees: an illustrative expected annual loss from a data breach.

    expected loss = P(breach in a year | score) x expected cost of a breach

Every number below is an assumption shown to the user next to the result, so it can be challenged and
recalibrated. It is a planning estimate, not an actuarial or insurance figure.
"""

import math
import os

from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import RiskInput, Score, User

router = APIRouter(prefix="/api")

# Average total cost of a data breach in India, in crore rupees (IBM Cost of a Data Breach Report 2024:
# INR 195 million). Override with RISK_BREACH_COST_CRORE when a newer figure is published.
BREACH_COST_CRORE = float(os.environ.get("RISK_BREACH_COST_CRORE", "19.5"))
# Assumed yearly chance of a material breach for a company scoring 700. To be calibrated with outcomes.
BASE_PROBABILITY = float(os.environ.get("RISK_BASE_PROBABILITY", "0.10"))
REFERENCE_REVENUE_CRORE = 1000.0
SENSITIVITY = {"low": 0.6, "standard": 1.0, "high": 1.6}


def probability(score: int) -> float:
    """Every 250 points below 700 multiplies the yearly chance by e (about 2.7); above 700 it falls."""
    return min(0.6, max(0.005, BASE_PROBABILITY * math.exp((700 - score) / 250)))


def estimate(score: int, revenue_crore: float | None, sensitivity: str = "standard") -> dict:
    size = 1.0 if not revenue_crore else min(6.0, max(0.15, (revenue_crore / REFERENCE_REVENUE_CRORE) ** 0.4))
    impact = BREACH_COST_CRORE * size * SENSITIVITY.get(sensitivity, 1.0)
    p = probability(score)
    expected = p * impact
    return {"probability": round(p, 4), "impact_crore": round(impact, 2), "expected_loss_crore": round(expected, 2),
            "range_crore": [round(expected * 0.5, 2), round(expected * 2, 2)],
            "assumptions": {"breach_cost_crore": BREACH_COST_CRORE,
                            "breach_cost_source": "IBM Cost of a Data Breach Report 2024, India average",
                            "base_probability_at_700": BASE_PROBABILITY,
                            "size_scaling": f"(revenue / {REFERENCE_REVENUE_CRORE:.0f} crore) ^ 0.4",
                            "sensitivity_multiplier": SENSITIVITY.get(sensitivity, 1.0)}}


def _latest(session: Session, entity_id: int) -> Score | None:
    return session.scalars(select(Score).where(Score.entity_id == entity_id)
                           .order_by(Score.created_at.desc(), Score.id.desc())).first()


def _inputs(session: Session, user: User, entity_id: int) -> RiskInput | None:
    return session.scalars(select(RiskInput).where(RiskInput.org_id == user.org_id,
                                                   RiskInput.entity_id == entity_id)).first()


def _result(session: Session, user: User, entity_id: int) -> dict:
    latest = _latest(session, entity_id)
    inp = _inputs(session, user, entity_id)
    revenue, sens = (inp.revenue_crore, inp.sensitivity) if inp else (None, "standard")
    out = {"revenue_crore": revenue, "sensitivity": sens}
    if latest:
        out.update(estimate(latest.overall, revenue, sens))
        out["score"] = latest.overall
    return out


@router.get("/entities/{entity_id}/risk")
def get_risk(entity_id: int, user: User = Depends(auth.current_user),
             session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    return _result(session, user, entity_id)


class RiskIn(BaseModel):
    revenue_crore: float | None = None
    sensitivity: str = "standard"

    @field_validator("revenue_crore")
    @classmethod
    def _rev(cls, v):
        if v is not None and not (0 < v < 10_000_000):
            raise ValueError("revenue must be a positive number of crore rupees")
        return v

    @field_validator("sensitivity")
    @classmethod
    def _sens(cls, v):
        if v not in SENSITIVITY:
            raise ValueError("sensitivity must be low, standard or high")
        return v


@router.put("/entities/{entity_id}/risk")
def set_risk(entity_id: int, body: RiskIn, user: User = Depends(auth.current_user),
             session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    inp = _inputs(session, user, entity_id) or RiskInput(org_id=user.org_id, entity_id=entity_id)
    inp.revenue_crore, inp.sensitivity = body.revenue_crore, body.sensitivity
    session.add(inp)
    session.commit()
    return _result(session, user, entity_id)
