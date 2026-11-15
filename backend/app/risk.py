"""Cyber risk in rupees: an illustrative expected annual loss from a data breach.

    expected loss = P(breach in a year | score) x expected cost of a breach

Every number below is an assumption shown to the user next to the result, so it can be challenged and
recalibrated. It is a planning estimate, not an actuarial or insurance figure.
"""

import math
import os
import threading
import time

import httpx

from fastapi import APIRouter, Depends
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import RiskInput, Score, User

router = APIRouter(prefix="/api")

# Rupees per US dollar and per euro. Fetched daily from the European Central Bank reference rates
# (via frankfurter.dev, free, no key); these fallbacks are used if the feed cannot be reached.
FALLBACK_RATES = {"USD": float(os.environ.get("RISK_USD_INR", "88.0")),
                  "EUR": float(os.environ.get("RISK_EUR_INR", "102.0")),
                  "GBP": 117.0, "AUD": 58.0, "SGD": 68.0, "JPY": 0.58, "CAD": 63.0, "CHF": 110.0}
ECB_SYMBOLS = ("USD", "EUR", "GBP", "AUD", "SGD", "JPY", "CAD", "CHF")
USD_PEGS = {"AED": 3.6725, "SAR": 3.75}  # fixed pegs to the US dollar


def _with_pegs(rates: dict) -> dict:
    return {**rates, **{c: round(rates["USD"] / peg, 4) for c, peg in USD_PEGS.items()}}
_rates_lock = threading.Lock()
_rates: dict = {"loaded": 0.0, "rates": None, "date": None}


def inr_rates() -> dict:
    """{'USD': rupees per dollar, 'EUR': rupees per euro, 'date': ..., 'source': ...}"""
    with _rates_lock:
        if time.time() - _rates["loaded"] < 12 * 3600 and _rates["rates"]:
            return {**_rates["rates"], "date": _rates["date"], "source": "European Central Bank"}
        try:
            resp = httpx.get("https://api.frankfurter.dev/v1/latest", params={"base": "INR", "symbols": ",".join(ECB_SYMBOLS)},
                             timeout=10.0, follow_redirects=True)
            resp.raise_for_status()
            data = resp.json()
            fetched = {k: round(1 / v, 4) for k, v in data["rates"].items() if k in ECB_SYMBOLS and v}
            _rates["rates"] = _with_pegs({**FALLBACK_RATES, **fetched})
            _rates["date"], _rates["loaded"] = data.get("date"), time.time()
            return {**_rates["rates"], "date": _rates["date"], "source": "European Central Bank"}
        except (httpx.HTTPError, ValueError, KeyError, ZeroDivisionError):
            _rates["loaded"] = time.time() - 12 * 3600 + 900  # retry in 15 minutes
            if _rates["rates"]:
                return {**_rates["rates"], "date": _rates["date"], "source": "European Central Bank"}
            return {**_with_pegs(FALLBACK_RATES), "date": None, "source": "fixed fallback rate"}


def convert(crore: float, rates: dict) -> dict:
    rupees = crore * 1e7
    out = {"INR": round(rupees)}
    for code in (*ECB_SYMBOLS, *USD_PEGS):
        if rates.get(code):
            out[code] = round(rupees / rates[code])
    return out

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


def estimate(score: int, revenue_crore: float | None, sensitivity: str = "standard",
             breach_cost_crore: float | None = None, breach_cost_source: str | None = None) -> dict:
    base_cost = breach_cost_crore or BREACH_COST_CRORE
    size = 1.0 if not revenue_crore else min(6.0, max(0.15, (revenue_crore / REFERENCE_REVENUE_CRORE) ** 0.4))
    impact = base_cost * size * SENSITIVITY.get(sensitivity, 1.0)
    p = probability(score)
    expected = p * impact
    return {"probability": round(p, 4), "impact_crore": round(impact, 2), "expected_loss_crore": round(expected, 2),
            "range_crore": [round(expected * 0.5, 2), round(expected * 2, 2)],
            "assumptions": {"breach_cost_crore": round(base_cost, 2),
                            "breach_cost_source": breach_cost_source or "IBM Cost of a Data Breach Report 2024, India average",
                            "base_probability_at_700": BASE_PROBABILITY,
                            "size_scaling": f"(revenue / {REFERENCE_REVENUE_CRORE:.0f} crore) ^ 0.4",
                            "sensitivity_multiplier": SENSITIVITY.get(sensitivity, 1.0)}}


# ---------- FAIR-style simulation ----------
# Factor Analysis of Information Risk (FAIR, an Open Group standard): yearly loss = number of loss events
# x size of each loss, each drawn from a range rather than a single guess. We simulate many years and
# report the spread, including the 1-in-20 and 1-in-100 bad years that a single average hides.
SIMULATIONS = 10_000
# Size of one loss as multiples of the average breach cost for the company: (min, most likely, max).
BREACH_PRIMARY = (0.15, 0.6, 2.5)      # response, recovery, notification, lost business
BREACH_SECONDARY = (0.05, 0.4, 1.5)    # regulatory penalties (e.g. DPDP Act), lawsuits, reputation
BREACH_SECONDARY_CHANCE = 0.3
RANSOMWARE_LOSS = (0.3, 1.0, 4.0)      # downtime, recovery and, sometimes, extortion
RANSOMWARE_RATE_AT_INDEX_1 = 0.2       # yearly attack rate for a company with susceptibility 1.0


def _pert(rng, lo: float, mode: float, hi: float) -> float:
    if hi <= lo:
        return lo
    a = 1 + 4 * (mode - lo) / (hi - lo)
    b = 1 + 4 * (hi - mode) / (hi - lo)
    return lo + rng.betavariate(a, b) * (hi - lo)


def _poisson(rng, lam: float) -> int:
    limit, k, prod = math.exp(-lam), 0, rng.random()
    while prod > limit:
        k += 1
        prod *= rng.random()
    return k


def fair_simulation(p_breach: float, impact_crore: float, ransomware_index: float | None = None,
                    n: int = SIMULATIONS, seed: int = 7) -> dict:
    import random

    rng = random.Random(seed)
    rate = -math.log(1 - min(p_breach, 0.95))
    r_rate = RANSOMWARE_RATE_AT_INDEX_1 * (ransomware_index or 0.0)
    years, breach_total, ransom_total = [], 0.0, 0.0
    for _ in range(n):
        loss = 0.0
        for _ in range(_poisson(rng, _pert(rng, 0.4 * rate, rate, 2.5 * rate))):
            one = _pert(rng, *BREACH_PRIMARY)
            if rng.random() < BREACH_SECONDARY_CHANCE:
                one += _pert(rng, *BREACH_SECONDARY)
            loss += one * impact_crore
        breach_total += loss
        if r_rate:
            r_loss = sum(_pert(rng, *RANSOMWARE_LOSS) * impact_crore
                         for _ in range(_poisson(rng, _pert(rng, 0.5 * r_rate, r_rate, 2 * r_rate))))
            ransom_total += r_loss
            loss += r_loss
        years.append(loss)
    years.sort()

    def q(x):
        return round(years[min(n - 1, int(x * n))], 2)

    top = max(years[-1], 0.01)
    thresholds = sorted({round(top * f, 2) for f in (0.02, 0.05, 0.1, 0.2, 0.35, 0.5, 0.75, 1.0)})
    curve = [{"crore": t, "probability": round(sum(1 for y in years if y > t) / n, 4)} for t in thresholds]
    return {"simulations": n, "mean_crore": round(sum(years) / n, 2), "median_crore": q(0.5),
            "p90_crore": q(0.9), "p95_crore": q(0.95), "p99_crore": q(0.99),
            "chance_of_any_loss": round(sum(1 for y in years if y > 0) / n, 4),
            "by_scenario": {"data_breach": round(breach_total / n, 2), "ransomware": round(ransom_total / n, 2)},
            "exceedance": curve,
            "assumptions": {"method": "FAIR (Open Group): loss event frequency x loss magnitude, Monte Carlo",
                            "breach_events_per_year": [round(0.4 * rate, 3), round(rate, 3), round(2.5 * rate, 3)],
                            "breach_loss_multiples": BREACH_PRIMARY, "secondary_loss_multiples": BREACH_SECONDARY,
                            "secondary_loss_chance": BREACH_SECONDARY_CHANCE,
                            "ransomware_attacks_per_year": round(r_rate, 3), "ransomware_loss_multiples": RANSOMWARE_LOSS}}


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
        from .orgsettings import settings_for

        rates = inr_rates()
        org = settings_for(session, user.org_id)
        cost_crore = org["breach_cost_usd_m"] * 1e6 * rates["USD"] / 1e7
        est = estimate(latest.overall, revenue, sens, cost_crore, org["breach_cost_source"])
        est["assumptions"]["breach_cost"] = convert(cost_crore, rates)
        est["assumptions"]["breach_cost_usd_m"] = org["breach_cost_usd_m"]
        est["default_currency"], est["home_country"] = org["currency"], org["country"]
        est["currencies"] = {
            "expected_loss": convert(est["expected_loss_crore"], rates),
            "range": [convert(v, rates) for v in est["range_crore"]],
            "impact": convert(est["impact_crore"], rates),
        }
        est["exchange_rates"] = rates
        from .models import Entity
        from .ransomware import for_entity

        rsi = for_entity(session, session.get(Entity, entity_id))["index"]
        fair = fair_simulation(est["probability"], est["impact_crore"], rsi, seed=entity_id)
        fair["ransomware_index"] = rsi
        fair["currencies"] = {k: convert(fair[k], rates) for k in ("mean_crore", "median_crore", "p90_crore", "p95_crore", "p99_crore")}
        fair["currencies"]["exceedance"] = [convert(pt["crore"], rates) for pt in fair["exceedance"]]
        est["fair"] = fair
        out.update(est)
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
