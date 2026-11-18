"""Privacy rights, the suppression list and data retention (BRS PRIV-002, PRIV-004, PRIV-005).

- Anyone can send a rights request from the public /privacy-request page: see the personal data we hold
  about them, correct it, delete it, or object to its use. The platform owner answers within 30 days
  (the deadline under India's DPDP Act rules and the GDPR's one month).
- To help answer, the owner can look up every place an email address appears, and erase it: free-report
  leads are deleted, and the address is removed from disputes, opt-out requests, questionnaires, vendor
  links, vendor contacts and fix owners. User accounts are not deleted here; people delete their own account
  in Account settings (or the owner does it from Team).
- The suppression list holds a SHA-256 hash of each address that must never be emailed or stored again.
  Every outgoing email and every public form checks it.
- Retention: a daily job deletes data we no longer need (see RETENTION). Scan results about companies are
  kept because they are not personal data; the audit log is kept because it is our security record.
"""

from __future__ import annotations

import hashlib
import re
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import auth, db
from .models import (Alert, Dispute, FreeReport, OptOutRequest, PrivacyRequest, Questionnaire, RemediationTask,
                     SessionToken, Suppression, User, VendorProfile, VendorShare)

router = APIRouter(prefix="/api")
KINDS = {"access": "See my data", "correct": "Correct my data", "delete": "Delete my data",
         "object": "Stop using my data / stop emailing me", "other": "Something else"}
ANSWER_DAYS = 30
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")

# what is deleted, and after how many days
RETENTION = {
    "expired_sessions": 7,          # sign-in sessions, counted from when they expired
    "free_report_leads": 365,       # public free-report requests (name, work email)
    "alerts": 730,                  # in-app alerts
    "closed_privacy_requests": 1095,  # kept 3 years as proof we answered
}


def email_hash(email: str) -> str:
    return hashlib.sha256((email or "").strip().lower().encode()).hexdigest()


def suppressed(session: Session, email: str | None) -> bool:
    if not email:
        return False
    return session.scalars(select(Suppression.id).where(Suppression.email_hash == email_hash(email))).first() is not None


def allowed_recipients(to: list[str]) -> list[str]:
    """Drop suppressed addresses before any email is sent. Opens its own session (callers run in threads)."""
    if not to:
        return []
    session = db.SessionLocal()
    try:
        hashes = set(session.scalars(select(Suppression.email_hash).where(Suppression.email_hash.in_([email_hash(t) for t in to]))))
        return [t for t in to if email_hash(t) not in hashes]
    finally:
        session.close()


def suppress(session: Session, email: str, reason: str) -> bool:
    if suppressed(session, email):
        return False
    session.add(Suppression(email_hash=email_hash(email), reason=reason[:200]))
    return True


# ---------- finding and erasing an address ----------

def _like(col, email: str):
    return col.ilike(email.strip())


def lookup(session: Session, email: str) -> dict:
    e = email.strip()
    users = session.scalars(select(User).where(_like(User.email, e))).all()
    return {
        "account": [{"name": u.name, "organisation": u.org.name if u.org else None, "role": u.role, "active": u.active,
                     "created_at": u.created_at.isoformat()} for u in users],
        "free_reports": len(session.scalars(select(FreeReport.id).where(_like(FreeReport.contact_email, e))).all()),
        "disputes": len(session.scalars(select(Dispute.id).where(_like(Dispute.contact_email, e))).all()),
        "opt_out_requests": len(session.scalars(select(OptOutRequest.id).where(_like(OptOutRequest.contact_email, e))).all()),
        "questionnaires": len(session.scalars(select(Questionnaire.id).where(_like(Questionnaire.recipient_email, e))).all()),
        "vendor_links": len(session.scalars(select(VendorShare.id).where(_like(VendorShare.recipient_email, e))).all()),
        "fix_owner": len(session.scalars(select(RemediationTask.id).where(_like(RemediationTask.assignee_email, e))).all()),
        "vendor_contact": sum(1 for p in session.scalars(select(VendorProfile))
                              if ((p.details or {}).get("contact_email") or "").lower() == e.lower()),
        "privacy_requests": len(session.scalars(select(PrivacyRequest.id).where(_like(PrivacyRequest.email, e))).all()),
        "suppressed": suppressed(session, e),
    }


REDACTED = "erased@privacy.invalid"


def erase(session: Session, email: str) -> dict:
    """Remove an address everywhere except user accounts and the audit log. Returns counts."""
    e = email.strip()
    n = {"free_reports": session.execute(delete(FreeReport).where(_like(FreeReport.contact_email, e))).rowcount}
    rows = session.scalars(select(Dispute).where(_like(Dispute.contact_email, e))).all()
    for r in rows:
        r.contact_email = None
    n["disputes"] = len(rows)
    rows = session.scalars(select(OptOutRequest).where(_like(OptOutRequest.contact_email, e))).all()
    for r in rows:
        r.contact_email = REDACTED
    n["opt_out_requests"] = len(rows)
    rows = session.scalars(select(Questionnaire).where(_like(Questionnaire.recipient_email, e))).all()
    for r in rows:
        r.recipient_email = REDACTED
    n["questionnaires"] = len(rows)
    rows = session.scalars(select(VendorShare).where(_like(VendorShare.recipient_email, e))).all()
    for r in rows:
        r.recipient_email, r.recipient_name = REDACTED, None
    n["vendor_links"] = len(rows)
    rows = session.scalars(select(RemediationTask).where(_like(RemediationTask.assignee_email, e))).all()
    for r in rows:
        r.assignee_email = None
    n["fix_owner"] = len(rows)
    k = 0
    for p in session.scalars(select(VendorProfile)):
        d = dict(p.details or {})
        if (d.get("contact_email") or "").lower() == e.lower():
            d["contact_email"], d["contact_name"] = None, None
            p.details = d
            k += 1
    n["vendor_contact"] = k
    return n


# ---------- retention ----------

def apply_retention(session: Session, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)

    def before(days: int) -> datetime:
        return now - timedelta(days=days)

    out = {
        "expired_sessions": session.execute(delete(SessionToken).where(SessionToken.expires_at < before(RETENTION["expired_sessions"]))).rowcount,
        "free_report_leads": session.execute(delete(FreeReport).where(FreeReport.created_at < before(RETENTION["free_report_leads"]))).rowcount,
        "alerts": session.execute(delete(Alert).where(Alert.created_at < before(RETENTION["alerts"]))).rowcount,
        "closed_privacy_requests": session.execute(delete(PrivacyRequest).where(
            PrivacyRequest.closed_at.is_not(None), PrivacyRequest.closed_at < before(RETENTION["closed_privacy_requests"]))).rowcount,
    }
    session.commit()
    return out


# ---------- API ----------

class RequestIn(BaseModel):
    kind: str
    email: str
    name: str | None = None
    details: str | None = None
    website: str | None = None  # honeypot

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in KINDS:
            raise ValueError("choose what you would like us to do")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip()
        if not _EMAIL_RE.match(v):
            raise ValueError("enter a valid email address")
        return v

    @field_validator("name", "details")
    @classmethod
    def _trim(cls, v: str | None) -> str | None:
        return (v or "").strip()[:4000] or None


@router.get("/public/privacy")
def privacy_facts() -> dict:
    return {"kinds": KINDS, "answer_days": ANSWER_DAYS, "retention_days": RETENTION}


@router.post("/public/privacy-request", status_code=202)
def submit(body: RequestIn, request: Request, session: Session = Depends(db.get_session)) -> dict:
    from .optout import limiter, public_daily

    if body.website:
        return {"status": "received"}
    client = request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0]
    if not limiter.allow("priv:" + client.strip()) or not public_daily.allow("all"):
        raise HTTPException(429, "too many requests; please try again later")
    session.add(PrivacyRequest(kind=body.kind, email=body.email, name=body.name, details=body.details,
                               due=date.today() + timedelta(days=ANSWER_DAYS)))
    session.commit()
    return {"status": "received", "answer_within_days": ANSWER_DAYS}


def _owner(user: User = Depends(auth.current_user)) -> User:
    if user.role != "owner":
        raise HTTPException(403, "owner only")
    return user


def _out(r: PrivacyRequest) -> dict:
    return {"id": r.id, "kind": r.kind, "kind_label": KINDS.get(r.kind, r.kind), "email": r.email, "name": r.name,
            "details": r.details, "status": r.status, "due": r.due.isoformat(), "overdue": r.status in ("new", "in_progress") and r.due < date.today(),
            "note": r.note, "result": r.result or {}, "created_at": r.created_at.isoformat(),
            "closed_at": r.closed_at.isoformat() if r.closed_at else None}


@router.get("/privacy-requests")
def list_requests(_: User = Depends(_owner), session: Session = Depends(db.get_session)) -> dict:
    rows = session.scalars(select(PrivacyRequest).order_by(PrivacyRequest.created_at.desc())).all()
    return {"requests": [_out(r) for r in rows], "suppressed": len(session.scalars(select(Suppression.id)).all()),
            "retention_days": RETENTION}


@router.get("/privacy-requests/{rid}/lookup")
def lookup_request(rid: int, _: User = Depends(_owner), session: Session = Depends(db.get_session)) -> dict:
    r = session.get(PrivacyRequest, rid)
    if r is None:
        raise HTTPException(404, "request not found")
    return lookup(session, r.email)


class DecideIn(BaseModel):
    status: str
    note: str | None = None
    erase: bool = False
    suppress: bool = False


@router.post("/privacy-requests/{rid}")
def decide(rid: int, body: DecideIn, user: User = Depends(_owner), session: Session = Depends(db.get_session)) -> dict:
    from .audit import record

    r = session.get(PrivacyRequest, rid)
    if r is None:
        raise HTTPException(404, "request not found")
    if body.status not in ("in_progress", "done", "rejected"):
        raise HTTPException(422, "status must be in_progress, done or rejected")
    if body.status == "rejected" and not (body.note or "").strip():
        raise HTTPException(422, "say why the request is refused; the person is entitled to know")
    result = dict(r.result or {})
    if body.erase:
        result["erased"] = erase(session, r.email)
    if body.suppress:
        suppress(session, r.email, f"privacy request {r.id}")
        result["suppressed"] = True
    r.status, r.note, r.result = body.status, (body.note or "").strip()[:2000] or r.note, result
    r.closed_at = datetime.now(timezone.utc) if body.status in ("done", "rejected") else None
    session.commit()
    record(session, user, "privacy_request", f"#{r.id} {r.kind} -> {r.status}" + (" (erased)" if body.erase else ""))
    return _out(r)
