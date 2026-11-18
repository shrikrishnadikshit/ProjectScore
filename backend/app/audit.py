"""Audit log of user and admin actions, BRS GEN-005 / NFR-010.

Every change made through the API (any POST, PUT, PATCH or DELETE by a signed-in user) is recorded with who,
what, when and from where, plus explicit events such as sign-in and MFA changes. Rows are chained: each
stores the SHA-256 of the previous row, so an edited or deleted row breaks the chain and /api/audit/verify
reports where. Passwords, codes and request bodies are never recorded.
"""

from __future__ import annotations

import csv
import hashlib
import io
import threading
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import AuditEvent, SessionToken, User

router = APIRouter(prefix="/api")
_lock = threading.Lock()
SKIP = ("/api/auth/login", "/api/auth/mfa", "/api/public/", "/api/auth/logout")


def _digest(prev: str, at: datetime, org_id, user_id, actor, action, target, status, ip) -> str:
    at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
    raw = "|".join(str(x if x is not None else "") for x in (prev, at.isoformat(), org_id, user_id, actor, action, target, status, ip))
    return hashlib.sha256(raw.encode()).hexdigest()


def record(session: Session, user: User | None, action: str, target: str | None = None, status: int | None = None,
           ip: str | None = None, org_id: int | None = None, actor: str | None = None) -> None:
    with _lock:
        last = session.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).first()
        prev = last.hash if last else "0" * 64
        at = datetime.now(timezone.utc)
        org = user.org_id if user else org_id
        who = user.email if user else actor
        row = AuditEvent(at=at, org_id=org, user_id=user.id if user else None, actor=who, action=action[:60],
                         target=(target or "")[:300] or None, status=status, ip=(ip or "")[:64] or None, prev_hash=prev)
        row.hash = _digest(prev, at, org, row.user_id, who, row.action, row.target, status, row.ip)
        session.add(row)
        session.commit()


def client_ip(request: Request) -> str | None:
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else None)


def from_request(request: Request, status: int) -> None:
    """Called by the middleware after each unsafe API request."""
    path = request.url.path
    if not path.startswith("/api/") or path.startswith(SKIP):
        return
    token = request.cookies.get(auth.COOKIE_NAME)
    if not token:
        return
    session = db.SessionLocal()
    try:
        row = session.scalars(select(SessionToken).where(SessionToken.token_hash == auth._token_hash(token))).first()
        if row is None:
            return
        record(session, row.user, f"{request.method} {path.split('/')[2]}", f"{request.method} {path}", status, client_ip(request))
    except Exception:  # the log must never break the request
        session.rollback()
    finally:
        session.close()


def verify_chain(session: Session) -> dict:
    prev, checked = "0" * 64, 0
    for row in session.scalars(select(AuditEvent).order_by(AuditEvent.id)).yield_per(500):
        if row.prev_hash != prev or row.hash != _digest(prev, row.at, row.org_id, row.user_id, row.actor, row.action,
                                                        row.target, row.status, row.ip):
            return {"ok": False, "checked": checked, "broken_at": row.id}
        prev, checked = row.hash, checked + 1
    return {"ok": True, "checked": checked}


def _rows(session: Session, user: User, days: int, q: str | None):
    stmt = select(AuditEvent).where(AuditEvent.at >= datetime.now(timezone.utc) - timedelta(days=max(1, min(days, 3650))))
    if user.role != "owner":
        stmt = stmt.where(AuditEvent.org_id == user.org_id)
    rows = session.scalars(stmt.order_by(AuditEvent.id.desc()).limit(5000)).all()
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in " ".join(str(x or "") for x in (r.actor, r.action, r.target, r.ip)).lower()]
    return rows


def _out(r: AuditEvent) -> dict:
    at = r.at if r.at.tzinfo else r.at.replace(tzinfo=timezone.utc)
    return {"id": r.id, "at": at.isoformat(), "actor": r.actor, "action": r.action, "target": r.target,
            "status": r.status, "ip": r.ip}


@router.get("/audit")
def list_events(days: int = 30, q: str | None = None, user: User = Depends(auth.require_admin),
                session: Session = Depends(db.get_session)) -> dict:
    rows = _rows(session, user, days, q)
    return {"events": [_out(r) for r in rows[:500]], "total": len(rows)}


@router.get("/audit/export")
def export(days: int = 90, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> Response:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "time_utc", "user", "action", "target", "status", "ip", "hash"])
    for r in _rows(session, user, days, None):
        w.writerow([r.id, _out(r)["at"], r.actor, r.action, r.target, r.status, r.ip, r.hash])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="audit-log.csv"'})


@router.get("/audit/verify")
def verify(user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    return verify_chain(session)
