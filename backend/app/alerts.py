"""Alerts when a rating falls or a serious new issue appears (BRS continuous monitoring).

Every organisation with the company in its portfolio gets an alert in the app. If RESEND_API_KEY and
ALERT_EMAIL_FROM are set, its active users are also emailed through Resend.
"""

import logging
import os
import threading

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from . import auth, db
from .models import Alert, Entity, Finding, PortfolioItem, Score, User

logger = logging.getLogger("projectscore.alerts")
router = APIRouter(prefix="/api")

GRADES = "ABCDF"


def score_drop_threshold() -> int:
    return int(os.environ.get("ALERT_SCORE_DROP", "20"))


def events(entity: Entity, previous: Score | None, current: Score, new_findings: list[Finding]) -> list[dict]:
    """Nothing on a company's first scan: everything would look new."""
    if previous is None:
        return []
    out = []
    drop = previous.overall - current.overall
    worse_grade = GRADES.index(current.grade) > GRADES.index(previous.grade)
    if drop >= score_drop_threshold() or worse_grade:
        out.append({"kind": "score_drop", "severity": "critical" if current.grade in "DF" and worse_grade else "warning",
                    "title": f"{entity.name}: score fell from {previous.overall} ({previous.grade}) to {current.overall} ({current.grade})",
                    "detail": None})
    dark = [f for f in new_findings if (f.evidence or {}).get("darkweb") and f.severity in ("critical", "high", "medium")]
    if dark:
        out.append({"kind": "dark_web", "severity": "critical" if any(f.code.startswith("ransomware_leak_") for f in dark) else "warning",
                    "title": f"{entity.name}: found on the dark web",
                    "detail": "\n".join(f.title for f in dark[:5])})
    serious = [f for f in new_findings if f.severity in ("critical", "high") and f not in dark]
    if serious:
        crit = any(f.severity == "critical" for f in serious)
        lines = [f"{f.severity.title()}: {f.title} ({f.asset_value})" for f in serious[:10]]
        if len(serious) > 10:
            lines.append(f"and {len(serious) - 10} more")
        out.append({"kind": "new_serious", "severity": "critical" if crit else "warning",
                    "title": f"{entity.name}: " + _count_text(serious),
                    "detail": "\n".join(lines)})
    return out


def _count_text(serious: list[Finding]) -> str:
    n_crit = sum(f.severity == "critical" for f in serious)
    n_high = len(serious) - n_crit
    parts = [f"{n} {label}" for n, label in ((n_crit, "critical"), (n_high, "high-severity")) if n]
    return f"new issue{'s' if len(serious) > 1 else ''}: " + " and ".join(parts)


def notify(session: Session, entity: Entity, previous: Score | None, current: Score,
           new_findings: list[Finding]) -> list[Alert]:
    evs = events(entity, previous, current, new_findings)
    if not evs:
        return []
    org_ids = session.scalars(select(PortfolioItem.org_id).where(PortfolioItem.entity_id == entity.id)).all()
    alerts = [Alert(org_id=o, entity_id=entity.id, **e) for o in set(org_ids) for e in evs]
    session.add_all(alerts)
    session.commit()
    if os.environ.get("RESEND_API_KEY") and os.environ.get("ALERT_EMAIL_FROM"):
        for org_id in set(org_ids):
            to = session.scalars(select(User.email).where(User.org_id == org_id, User.active.is_(True))).all()
            if to:
                threading.Thread(target=send_email, args=(list(to), entity.id, evs), daemon=True).start()
    return alerts


def send_email(to: list[str], entity_id: int, evs: list[dict]) -> bool:
    base = os.environ.get("APP_URL", "https://projectscore.onrender.com").rstrip("/")
    subject = evs[0]["title"] if len(evs) == 1 else f"{evs[0]['title'].split(':')[0]}: {len(evs)} rating alerts"
    body = "\n\n".join(e["title"] + ("\n" + e["detail"] if e["detail"] else "") for e in evs)
    body += f"\n\nSee the details: {base}/entities/{entity_id}\n\nYou get this email because the company is in your ProjectScore portfolio."
    try:
        resp = httpx.post("https://api.resend.com/emails", timeout=20.0,
                          headers={"Authorization": f"Bearer {os.environ['RESEND_API_KEY']}"},
                          json={"from": os.environ["ALERT_EMAIL_FROM"], "to": to, "subject": subject, "text": body})
        resp.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        logger.warning("alert email failed: %s", exc)
        return False


def _out(a: Alert) -> dict:
    return {"id": a.id, "entity_id": a.entity_id, "kind": a.kind, "severity": a.severity, "title": a.title,
            "detail": a.detail, "read": a.read, "created_at": a.created_at.isoformat()}


@router.get("/alerts")
def list_alerts(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> list[dict]:
    rows = session.scalars(select(Alert).where(Alert.org_id == user.org_id)
                           .order_by(Alert.created_at.desc(), Alert.id.desc()).limit(200)).all()
    return [_out(a) for a in rows]


@router.get("/alerts/unread-count")
def unread_count(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    n = session.scalar(select(func.count()).select_from(Alert).where(Alert.org_id == user.org_id, Alert.read.is_(False)))
    return {"count": n or 0}


@router.post("/alerts/read-all")
def read_all(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    session.execute(update(Alert).where(Alert.org_id == user.org_id, Alert.read.is_(False)).values(read=True))
    session.commit()
    return {"status": "ok"}


@router.post("/alerts/{alert_id}/read")
def read_one(alert_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    a = session.get(Alert, alert_id)
    if a is None or a.org_id != user.org_id:
        raise HTTPException(404, "alert not found")
    a.read = True
    session.commit()
    return _out(a)
