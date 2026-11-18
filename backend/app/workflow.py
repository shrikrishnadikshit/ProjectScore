"""Fix tracking, risk acceptance and per-organisation thresholds (BRS EXM-030/031, TPRM-006/007/020).

- A fix task is one issue type at one company, with an owner (a colleague or the vendor's contact), a due
  date set from the organisation's deadlines per severity, and a status. When a rescan no longer sees the
  issue, the task closes itself as "verified"; if a task marked fixed is still seen, it is reopened.
- Time to fix (MTTR) is measured from task creation to verified closure.
- A risk acceptance records a decision to live with a risk for a period: requested with a reason and
  compensating controls, approved or rejected by an admin, and expired automatically.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import (Alert, Entity, Finding, OrgPreferences, PortfolioItem, RemediationTask, RiskAcceptance, User)

router = APIRouter(prefix="/api")

DEFAULTS = {
    "sla_days": {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365},
    "score_drop": 20,
    "alert_grade_change": True,
    "alert_new_critical": True,
    "alert_new_high": True,
    "rescan_days": 1,
}


def _env_defaults() -> dict:
    import os

    return {"score_drop": int(os.environ.get("ALERT_SCORE_DROP", "20")),
            "rescan_days": int(os.environ.get("RESCAN_DAYS", "1"))}
STATUSES = ("open", "in_progress", "fixed", "verified", "accepted", "wont_fix")
CLOSED = ("verified", "accepted", "wont_fix")


# ---------- preferences ----------

def prefs(session: Session, org_id: int) -> dict:
    row = session.get(OrgPreferences, org_id)
    s = (row.settings if row else None) or {}
    out = {**DEFAULTS, **_env_defaults(), **{k: v for k, v in s.items() if k in DEFAULTS}}
    out["sla_days"] = {**DEFAULTS["sla_days"], **(s.get("sla_days") or {})}
    return out


class PrefsIn(BaseModel):
    sla_days: dict[str, int] | None = None
    score_drop: int | None = None
    alert_grade_change: bool | None = None
    alert_new_critical: bool | None = None
    alert_new_high: bool | None = None
    rescan_days: int | None = None


@router.get("/org/preferences")
def get_prefs(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    return prefs(session, user.org_id)


@router.put("/org/preferences")
def set_prefs(body: PrefsIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    cur = prefs(session, user.org_id)
    if body.sla_days is not None:
        for k, v in body.sla_days.items():
            if k in cur["sla_days"]:
                if not 1 <= int(v) <= 730:
                    raise HTTPException(422, "deadlines must be between 1 and 730 days")
                cur["sla_days"][k] = int(v)
    if body.score_drop is not None:
        if not 5 <= body.score_drop <= 300:
            raise HTTPException(422, "the score-drop alert must be between 5 and 300 points")
        cur["score_drop"] = body.score_drop
    if body.rescan_days is not None:
        if body.rescan_days not in (1, 3, 7):
            raise HTTPException(422, "rescan every 1, 3 or 7 days")
        cur["rescan_days"] = body.rescan_days
    for k in ("alert_grade_change", "alert_new_critical", "alert_new_high"):
        if getattr(body, k) is not None:
            cur[k] = getattr(body, k)
    row = session.get(OrgPreferences, user.org_id) or OrgPreferences(org_id=user.org_id)
    row.settings, row.updated_at = cur, datetime.now(timezone.utc)
    session.add(row)
    session.commit()
    return cur


# ---------- fix tasks ----------

def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _log(t: RemediationTask, who: str, action: str, note: str | None = None) -> None:
    t.history = (t.history or []) + [{"at": datetime.now(timezone.utc).isoformat(), "by": who, "action": action, "note": note}]


def task_out(session: Session, t: RemediationTask, names: dict[int, str] | None = None, today: date | None = None) -> dict:
    today = today or date.today()
    assignee = session.get(User, t.assignee_id) if t.assignee_id else None
    return {"id": t.id, "entity_id": t.entity_id, "company": (names or {}).get(t.entity_id) or (session.get(Entity, t.entity_id).name),
            "code": t.code, "title": t.title, "severity": t.severity, "status": t.status,
            "assignee": (assignee.name or assignee.email) if assignee else t.assignee_email, "assignee_id": t.assignee_id,
            "assignee_email": t.assignee_email, "due": t.due.isoformat() if t.due else None,
            "overdue": bool(t.due and t.due < today and t.status not in CLOSED), "note": t.note,
            "created_at": _aware(t.created_at).isoformat(), "closed_at": _aware(t.closed_at).isoformat() if t.closed_at else None,
            "history": t.history or []}


class TaskIn(BaseModel):
    entity_id: int
    code: str
    assignee_id: int | None = None
    assignee_email: str | None = None
    due: date | None = None
    note: str | None = None


class TaskUpdate(BaseModel):
    status: str | None = None
    assignee_id: int | None = None
    assignee_email: str | None = None
    due: date | None = None
    note: str | None = None


def _own_task(session: Session, user: User, tid: int) -> RemediationTask:
    t = session.get(RemediationTask, tid)
    if t is None or t.org_id != user.org_id:
        raise HTTPException(404, "task not found")
    return t


def _check_assignee(session: Session, user: User, assignee_id: int | None, email: str | None) -> str | None:
    if assignee_id is not None:
        a = session.get(User, assignee_id)
        if a is None or a.org_id != user.org_id:
            raise HTTPException(422, "that person is not in your organisation")
    if email:
        email = email.strip()
        if "@" not in email or len(email) > 320:
            raise HTTPException(422, "not a valid email")
    return email or None


@router.post("/tasks", status_code=201)
def create_task(body: TaskIn, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    item = _portfolio_item(session, user, body.entity_id)
    fs = session.scalars(select(Finding).where(Finding.entity_id == body.entity_id, Finding.code == body.code,
                                               Finding.status == "open")).all()
    if not fs:
        raise HTTPException(404, "no open findings of this type")
    if session.scalars(select(RemediationTask).where(RemediationTask.org_id == user.org_id, RemediationTask.entity_id == body.entity_id,
                                                     RemediationTask.code == body.code)).first():
        raise HTTPException(409, "there is already a task for this issue")
    email = _check_assignee(session, user, body.assignee_id, body.assignee_email)
    order = ["critical", "high", "medium", "low", "info"]
    worst = min((f.severity for f in fs), key=lambda s: order.index(s) if s in order else 9)
    due = body.due or date.today() + timedelta(days=prefs(session, user.org_id)["sla_days"].get(worst, 90))
    t = RemediationTask(org_id=user.org_id, entity_id=body.entity_id, code=body.code, title=fs[0].title, severity=worst,
                        assignee_id=body.assignee_id, assignee_email=email, due=due,
                        note=(body.note or "").strip()[:2000] or None, created_by=user.id, history=[])
    _log(t, user.name or user.email, "created", f"due {due.isoformat()}")
    session.add(t)
    session.commit()
    return task_out(session, t, {item.entity_id: item.entity.name})


@router.get("/tasks")
def list_tasks(entity_id: int | None = None, mine: bool = False, open_only: bool = True,
               user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    stmt = select(RemediationTask).where(RemediationTask.org_id == user.org_id)
    if entity_id:
        stmt = stmt.where(RemediationTask.entity_id == entity_id)
    if mine:
        stmt = stmt.where(RemediationTask.assignee_id == user.id)
    rows = session.scalars(stmt.order_by(RemediationTask.due)).all()
    names = {i.entity_id: i.entity.name for i in session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id))}
    out = [task_out(session, t, names) for t in rows if not open_only or t.status not in CLOSED]
    return {"tasks": out, "stats": stats(session, user.org_id)}


@router.patch("/tasks/{tid}")
def update_task(tid: int, body: TaskUpdate, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    t = _own_task(session, user, tid)
    who = user.name or user.email
    if body.status is not None:
        if body.status not in STATUSES or body.status in ("verified", "accepted"):
            raise HTTPException(422, "status must be open, in_progress, fixed or wont_fix (verified is set by a rescan, accepted by a risk acceptance)")
        if body.status == "wont_fix" and user.role not in ("admin", "owner"):
            raise HTTPException(403, "only admins can close a task without a fix; request a risk acceptance instead")
        t.status = body.status
        t.closed_at = datetime.now(timezone.utc) if body.status in CLOSED else None
        _log(t, who, f"marked {body.status.replace('_', ' ')}", body.note)
    if body.assignee_id is not None or body.assignee_email is not None:
        t.assignee_email = _check_assignee(session, user, body.assignee_id, body.assignee_email)
        t.assignee_id = body.assignee_id
        _log(t, who, "reassigned")
    if body.due is not None:
        t.due = body.due
        _log(t, who, "due date changed", body.due.isoformat())
    if body.note is not None and body.status is None:
        t.note = body.note.strip()[:2000] or None
        _log(t, who, "note", t.note)
    session.commit()
    return task_out(session, t)


def verify_after_scan(session: Session, entity: Entity) -> int:
    """Close tasks whose issue a rescan no longer sees; reopen 'fixed' tasks it still sees."""
    open_codes = {c for (c,) in session.execute(select(Finding.code).where(Finding.entity_id == entity.id, Finding.status == "open"))}
    changed = 0
    for t in session.scalars(select(RemediationTask).where(RemediationTask.entity_id == entity.id,
                                                           RemediationTask.status.in_(("open", "in_progress", "fixed")))):
        if t.code not in open_codes:
            t.status, t.closed_at = "verified", datetime.now(timezone.utc)
            _log(t, "ProjectScore", "verified by rescan")
            changed += 1
        elif t.status == "fixed":
            t.status = "in_progress"
            _log(t, "ProjectScore", "rescan still sees the issue; reopened")
            changed += 1
    session.commit()
    return changed


def stats(session: Session, org_id: int, today: date | None = None) -> dict:
    today = today or date.today()
    rows = session.scalars(select(RemediationTask).where(RemediationTask.org_id == org_id)).all()
    open_rows = [t for t in rows if t.status not in CLOSED]
    done = [t for t in rows if t.status == "verified" and t.closed_at]
    days = [(_aware(t.closed_at) - _aware(t.created_at)).total_seconds() / 86400 for t in done]
    by_sev = {}
    for t in done:
        by_sev.setdefault(t.severity, []).append((_aware(t.closed_at) - _aware(t.created_at)).total_seconds() / 86400)
    on_time = [t for t in done if t.due and _aware(t.closed_at).date() <= t.due]
    return {"open": len(open_rows), "overdue": sum(1 for t in open_rows if t.due and t.due < today),
            "verified": len(done), "mttr_days": round(sum(days) / len(days), 1) if days else None,
            "mttr_by_severity": {k: round(sum(v) / len(v), 1) for k, v in by_sev.items()},
            "on_time_pct": round(100 * len(on_time) / len(done)) if done else None}


def overdue_alerts(session: Session, today: date | None = None) -> int:
    """One alert per task on the day after it falls overdue."""
    today = today or date.today()
    n = 0
    for t in session.scalars(select(RemediationTask).where(RemediationTask.due < today,
                                                           RemediationTask.status.in_(("open", "in_progress", "fixed")))):
        if any(h.get("action") == "overdue alert" for h in t.history or []):
            continue
        name = session.get(Entity, t.entity_id).name
        session.add(Alert(org_id=t.org_id, entity_id=t.entity_id, kind="task_overdue", severity="warning",
                          title=f"{name}: fix overdue for \"{t.title}\"", detail=f"Due {t.due.isoformat()}."))
        _log(t, "ProjectScore", "overdue alert")
        n += 1
    session.commit()
    return n


# ---------- risk acceptance ----------

class AcceptIn(BaseModel):
    entity_id: int
    code: str | None = None
    reason: str
    controls: str | None = None
    expires_on: date


class DecideIn(BaseModel):
    approve: bool
    note: str | None = None


def acc_out(session: Session, a: RiskAcceptance) -> dict:
    req, appr = session.get(User, a.requested_by) if a.requested_by else None, session.get(User, a.approver_id) if a.approver_id else None
    return {"id": a.id, "entity_id": a.entity_id, "company": session.get(Entity, a.entity_id).name, "code": a.code,
            "scope": "Whole vendor" if not a.code else a.code, "reason": a.reason, "controls": a.controls, "status": a.status,
            "requested_by": (req.name or req.email) if req else None, "approver": (appr.name or appr.email) if appr else None,
            "self_approved": bool(a.approver_id and a.approver_id == a.requested_by),
            "decided_at": _aware(a.decided_at).isoformat() if a.decided_at else None,
            "expires_on": a.expires_on.isoformat(), "created_at": _aware(a.created_at).isoformat()}


@router.post("/acceptances", status_code=201)
def request_acceptance(body: AcceptIn, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, body.entity_id)
    if len(body.reason.strip()) < 10:
        raise HTTPException(422, "please explain why the risk is acceptable")
    if not date.today() < body.expires_on <= date.today() + timedelta(days=366):
        raise HTTPException(422, "the expiry must be within the next 12 months")
    a = RiskAcceptance(org_id=user.org_id, entity_id=body.entity_id, code=(body.code or None), reason=body.reason.strip()[:2000],
                       controls=(body.controls or "").strip()[:2000] or None, expires_on=body.expires_on, requested_by=user.id)
    session.add(a)
    session.commit()
    return acc_out(session, a)


@router.get("/acceptances")
def list_acceptances(entity_id: int | None = None, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> list[dict]:
    stmt = select(RiskAcceptance).where(RiskAcceptance.org_id == user.org_id)
    if entity_id:
        stmt = stmt.where(RiskAcceptance.entity_id == entity_id)
    return [acc_out(session, a) for a in session.scalars(stmt.order_by(RiskAcceptance.created_at.desc())).all()]


@router.post("/acceptances/{aid}/decide")
def decide(aid: int, body: DecideIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    a = session.get(RiskAcceptance, aid)
    if a is None or a.org_id != user.org_id:
        raise HTTPException(404, "not found")
    if a.status != "pending":
        raise HTTPException(409, "already decided")
    a.status = "approved" if body.approve else "rejected"
    a.approver_id, a.decided_at = user.id, datetime.now(timezone.utc)
    if body.approve and a.code:
        t = session.scalars(select(RemediationTask).where(RemediationTask.org_id == a.org_id, RemediationTask.entity_id == a.entity_id,
                                                          RemediationTask.code == a.code)).first()
        if t and t.status not in CLOSED:
            t.status, t.closed_at = "accepted", datetime.now(timezone.utc)
            _log(t, user.name or user.email, "risk accepted", f"until {a.expires_on.isoformat()}")
    session.commit()
    return acc_out(session, a)


@router.post("/acceptances/{aid}/revoke")
def revoke(aid: int, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    a = session.get(RiskAcceptance, aid)
    if a is None or a.org_id != user.org_id:
        raise HTTPException(404, "not found")
    a.status = "revoked"
    _reopen(session, a, user.name or user.email, "acceptance revoked")
    session.commit()
    return acc_out(session, a)


def _reopen(session: Session, a: RiskAcceptance, who: str, why: str) -> None:
    if not a.code:
        return
    t = session.scalars(select(RemediationTask).where(RemediationTask.org_id == a.org_id, RemediationTask.entity_id == a.entity_id,
                                                      RemediationTask.code == a.code, RemediationTask.status == "accepted")).first()
    if t:
        t.status, t.closed_at = "open", None
        _log(t, who, why)


def expire_acceptances(session: Session, today: date | None = None) -> int:
    today = today or date.today()
    n = 0
    for a in session.scalars(select(RiskAcceptance).where(RiskAcceptance.status == "approved", RiskAcceptance.expires_on < today)):
        a.status = "expired"
        _reopen(session, a, "ProjectScore", "risk acceptance expired")
        name = session.get(Entity, a.entity_id).name
        session.add(Alert(org_id=a.org_id, entity_id=a.entity_id, kind="acceptance_expired", severity="warning",
                          title=f"{name}: risk acceptance expired", detail=f"{'Whole vendor' if not a.code else a.code}. Review it again."))
        n += 1
    session.commit()
    return n


def accepted_codes(session: Session, org_id: int, entity_id: int) -> set[str]:
    return {a.code for a in session.scalars(select(RiskAcceptance).where(
        RiskAcceptance.org_id == org_id, RiskAcceptance.entity_id == entity_id, RiskAcceptance.status == "approved"))
            if a.code}


# ---------- residual risk ----------

def residual(inherent: int | None, score: int | None, questionnaire: int | None, critical: int, high: int) -> dict | None:
    """Residual risk 0-100: the inherent risk scaled by how weak the vendor's controls look.

    Control weakness blends the rating (50%), questionnaire answers (30%, when answered) and open
    critical/high issues (20%). Strong controls bring the residual down to 30% of the inherent risk at most."""
    if inherent is None or score is None:
        return None
    parts = [((900 - score) / 6, 0.5), (min(100, critical * 25 + high * 10), 0.2)]
    if questionnaire is not None:
        parts.append((100 - questionnaire, 0.3))
    weakness = sum(v * w for v, w in parts) / sum(w for _, w in parts)
    value = round(inherent * (0.3 + 0.7 * weakness / 100))
    level = "critical" if value >= 60 else "high" if value >= 40 else "medium" if value >= 20 else "low"
    return {"score": value, "level": level, "weakness": round(weakness),
            "inputs": {"inherent": inherent, "rating": score, "questionnaire": questionnaire, "critical": critical, "high": high}}


@router.get("/colleagues")
def colleagues(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> list[dict]:
    """People in your organisation a fix can be assigned to."""
    rows = session.scalars(select(User).where(User.org_id == user.org_id, User.active.is_(True)).order_by(User.email)).all()
    return [{"id": u.id, "name": u.name or u.email, "email": u.email} for u in rows]
