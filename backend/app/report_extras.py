"""Extra sections for the PDF report: industry comparison, 12-month trend, ransomware and incident risk,
and publicly disclosed incidents. Gathered here so report.py only does layout."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
from statistics import mean

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import ransomware
from .benchmark import MIN_GROUP, latest_scores
from .models import Entity, Finding, Incident

BIN = 50
LOW, HIGH = 300, 900
INCIDENT_MONTHS = 18


def _distribution(values: list[int]) -> list[dict]:
    """Share of the group in each 50-point range. Only called for groups of MIN_GROUP or more."""
    bins = []
    for start in range(LOW, HIGH, BIN):
        end = start + BIN
        n = sum(1 for v in values if start <= v < end or (end == HIGH and v == HIGH))
        bins.append({"from": start, "to": end - 1 if end < HIGH else HIGH, "share": round(100 * n / len(values), 1)})
    return bins


def peers(session: Session, entity: Entity) -> dict | None:
    """Industry average and distribution. Falls back to all rated companies when the industry is unknown
    or has fewer than MIN_GROUP rated companies, and says which group was used."""
    scores = latest_scores(session)
    if entity.id not in scores:
        return None
    score = scores[entity.id][0]
    industry = entity.industry
    group = [s for s, ind in scores.values() if industry and ind == industry]
    label = industry
    if len(group) < MIN_GROUP:
        group = [s for s, _ in scores.values()]
        label = None
    if len(group) < MIN_GROUP:
        return {"group": None, "count": len(group), "min_group": MIN_GROUP, "industry": industry}
    others = sorted(group)
    below = sum(v < score for v in others)
    return {"group": label or "All rated companies", "industry": industry, "fallback": label is None and bool(industry),
            "count": len(group), "average": round(mean(group)), "percentile": round(100 * below / len(group)),
            "distribution": _distribution(group), "min_group": MIN_GROUP}


def trend(history: list[dict], now: datetime) -> dict:
    """Scores in the last 12 months, with the highest and lowest and their dates."""
    start = now - timedelta(days=365)
    points = []
    for h in history:
        at = datetime.fromisoformat(h["created_at"])
        at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
        if at >= start:
            points.append({"at": at, "score": h["overall"]})
    if not points:
        return {"points": [], "start": start, "end": now}
    hi = max(points, key=lambda p: (p["score"], p["at"]))
    lo = min(points, key=lambda p: (p["score"], p["at"]))
    return {"points": points, "start": start, "end": now, "highest": hi, "lowest": lo,
            "change": points[-1]["score"] - points[0]["score"]}


# Score bands to incident risk. Published studies of outside-in ratings (vendors and insurers) report that
# companies with lower ratings have more breaches; until our own incident log is large enough to calibrate,
# this is a plain banding of our score and is labelled as indicative.
INCIDENT_BANDS = [(800, "Low", "Rated 800 or more: few outside signs of risk."),
                  (700, "Moderate", "Rated 700 to 799: some weaknesses an attacker could use."),
                  (600, "Elevated", "Rated 600 to 699: material weaknesses; incidents are more common at this level."),
                  (0, "High", "Rated below 600: serious weaknesses; incidents are most common at this level.")]


def incident_risk(score: int | None) -> dict | None:
    if score is None:
        return None
    for floor, level, text in INCIDENT_BANDS:
        if score >= floor:
            return {"level": level, "text": text}
    return None


def disclosed_incidents(session: Session, entity: Entity, now: datetime) -> dict:
    """Public incidents in the last 18 months: incidents recorded from news and regulators, data breaches
    published by Have I Been Pwned, and ransomware leak-site listings."""
    start = (now - timedelta(days=round(INCIDENT_MONTHS * 30.44))).date()
    events = []
    for i in session.scalars(select(Incident).where(Incident.entity_id == entity.id)).all():
        d = i.occurred_on.date()
        if d >= start:
            events.append({"date": d, "kind": i.kind.capitalize(), "text": i.description[:200], "source": "Incident record"})
    for f in session.scalars(select(Finding).where(Finding.entity_id == entity.id)).all():
        ev = f.evidence or {}
        if not ev.get("event_date") or not (f.code.startswith("breach_") or f.code.startswith("ransomware_leak_")):
            continue
        try:
            d = date.fromisoformat(str(ev["event_date"])[:10])
        except ValueError:
            continue
        if d < start:
            continue
        kind = "Data breach" if f.code.startswith("breach_") else "Ransomware leak site"
        events.append({"date": d, "kind": kind, "text": f.title, "source": ev.get("source") or ""})
    events.sort(key=lambda e: e["date"])
    return {"start": start, "end": now.date(), "events": events}


def gather(session: Session, entity: Entity, history: list[dict], now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    score = history[-1]["overall"] if history else None
    return {"peers": peers(session, entity), "trend": trend(history, now),
            "ransomware": ransomware.for_entity(session, entity) if history else None,
            "incident_risk": incident_risk(score), "incidents": disclosed_incidents(session, entity, now)}
