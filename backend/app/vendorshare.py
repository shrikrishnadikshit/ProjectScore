"""Vendor collaboration: share a company's issues with that company and let it reply to each one.

A customer sends a private link to a contact at the vendor. Without an account, the vendor sees the issues
we found on its systems with plain-language fix advice, marks each one (fixed, working on it, not ours,
accepted risk) with a comment, and can ask for a rescan to prove a fix. The customer sees every reply
on the company's page and gets an alert. Links expire after 30 days and can be revoked.
"""

from __future__ import annotations

import os
import secrets
import threading
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Alert, Entity, Finding, Organization, Score, User, VendorShare
from .optout import _EMAIL_RE
from .remediation import guidance

router = APIRouter(prefix="/api")
EXPIRES = timedelta(days=30)
RESCAN_EVERY = timedelta(hours=6)
STATUSES = {"fixed": "Fixed", "in_progress": "Working on it", "not_ours": "Not our system",
            "accepted_risk": "Accepted risk"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _findings(session: Session, share: VendorShare) -> list[Finding]:
    responded = [int(k) for k in (share.responses or {}) if str(k).isdigit()]
    rows = session.scalars(select(Finding).where(Finding.entity_id == share.entity_id,
                                                 (Finding.status == "open") | Finding.id.in_(responded))).all()
    return sorted(rows, key=lambda f: (f.status != "open", SEV_ORDER.get(f.severity, 9), f.title))


def _finding_out(f: Finding, share: VendorShare, with_advice: bool) -> dict:
    out = {"id": f.id, "title": f.title, "severity": f.severity, "asset": f.asset_value, "risk_factor": f.risk_factor,
           "status": f.status, "first_seen": _aware(f.first_seen).isoformat(),
           "response": (share.responses or {}).get(str(f.id))}
    if with_advice:
        g = guidance(f.code)
        out["why"], out["fix"] = g.get("why"), g.get("fix", [])
    return out


def _out(session: Session, s: VendorShare, detail: bool = False) -> dict:
    responses = s.responses or {}
    expired = datetime.now(timezone.utc) - _aware(s.created_at) > EXPIRES
    out = {"id": s.id, "entity_id": s.entity_id, "recipient_email": s.recipient_email,
           "recipient_name": s.recipient_name, "link_path": f"/v/{s.token}",
           "state": "revoked" if s.revoked else "expired" if expired else "active",
           "created_at": _aware(s.created_at).isoformat(),
           "last_viewed_at": _aware(s.last_viewed_at).isoformat() if s.last_viewed_at else None,
           "replies": len(responses),
           "by_status": {k: sum(1 for r in responses.values() if r.get("status") == k) for k in STATUSES}}
    if detail:
        out["findings"] = [_finding_out(f, s, False) for f in _findings(session, s)]
    return out


class ShareIn(BaseModel):
    recipient_email: str
    recipient_name: str | None = None
    message: str | None = None

    @field_validator("recipient_email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip()
        if not _EMAIL_RE.match(v):
            raise ValueError("not a valid email")
        return v


def _email_link(s: VendorShare, entity_name: str, org_name: str) -> None:
    if not (os.environ.get("RESEND_API_KEY") and os.environ.get("ALERT_EMAIL_FROM")):
        return
    from .privacy import allowed_recipients

    if not allowed_recipients([s.recipient_email]):
        return
    import httpx

    base = os.environ.get("APP_URL", "https://projectscore.onrender.com").rstrip("/")
    body = (f"{org_name} monitors the external security of {entity_name} and would like your help fixing some issues "
            f"found on your public systems.\n\n" + (f"Message from {org_name}: {s.message}\n\n" if s.message else "")
            + f"See the issues, with advice on fixing each one, and reply here: {base}/v/{s.token}\n\n"
            "No account is needed. The link expires in 30 days.")
    try:
        httpx.post("https://api.resend.com/emails", timeout=20.0,
                   headers={"Authorization": f"Bearer {os.environ['RESEND_API_KEY']}"},
                   json={"from": os.environ["ALERT_EMAIL_FROM"], "to": [s.recipient_email],
                         "subject": f"Security issues found on {entity_name}: request from {org_name}",
                         "text": body}).raise_for_status()
    except httpx.HTTPError:
        pass


@router.post("/entities/{entity_id}/vendor-shares", status_code=201)
def create_share(entity_id: int, body: ShareIn, user: User = Depends(auth.require_admin),
                 session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    item = _portfolio_item(session, user, entity_id)
    s = VendorShare(org_id=user.org_id, entity_id=entity_id, token=secrets.token_urlsafe(24),
                    recipient_email=body.recipient_email, recipient_name=(body.recipient_name or "").strip()[:255] or None,
                    message=(body.message or "").strip()[:2000] or None, created_by=user.id, responses={})
    session.add(s)
    session.commit()
    threading.Thread(target=_email_link, args=(s, item.entity.name, user.org.name), daemon=True).start()
    return _out(session, s)


@router.get("/entities/{entity_id}/vendor-shares")
def list_shares(entity_id: int, user: User = Depends(auth.current_user),
                session: Session = Depends(db.get_session)) -> list[dict]:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    rows = session.scalars(select(VendorShare).where(VendorShare.org_id == user.org_id, VendorShare.entity_id == entity_id)
                           .order_by(VendorShare.created_at.desc())).all()
    return [_out(session, s, detail=True) for s in rows]


@router.post("/vendor-shares/{share_id}/revoke")
def revoke_share(share_id: int, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    s = session.get(VendorShare, share_id)
    if s is None or s.org_id != user.org_id:
        raise HTTPException(404, "link not found")
    s.revoked = True
    session.commit()
    return _out(session, s)


# ---------- public, for the vendor ----------

def _by_token(session: Session, token: str) -> VendorShare:
    s = session.scalars(select(VendorShare).where(VendorShare.token == token)).first()
    if s is None or s.revoked or datetime.now(timezone.utc) - _aware(s.created_at) > EXPIRES:
        raise HTTPException(404, "this link is not valid, has expired or was withdrawn")
    return s


@router.get("/public/vendor-share/{token}")
def public_get(token: str, session: Session = Depends(db.get_session)) -> dict:
    s = _by_token(session, token)
    entity, org = session.get(Entity, s.entity_id), session.get(Organization, s.org_id)
    latest = session.scalars(select(Score).where(Score.entity_id == s.entity_id)
                             .order_by(Score.created_at.desc(), Score.id.desc())).first()
    s.last_viewed_at = datetime.now(timezone.utc)
    session.commit()
    return {"company": entity.name, "domain": entity.primary_domain, "requested_by": org.name if org else None,
            "message": s.message, "score": latest.overall if latest else None, "grade": latest.grade if latest else None,
            "scanned_at": _aware(latest.created_at).isoformat() if latest else None,
            "statuses": STATUSES, "findings": [_finding_out(f, s, True) for f in _findings(session, s)],
            "can_rescan": s.last_rescan_at is None or datetime.now(timezone.utc) - _aware(s.last_rescan_at) > RESCAN_EVERY}


class ReplyIn(BaseModel):
    status: str
    comment: str | None = None

    @field_validator("status")
    @classmethod
    def _status(cls, v: str) -> str:
        if v not in STATUSES:
            raise ValueError("unknown status")
        return v


@router.put("/public/vendor-share/{token}/findings/{finding_id}")
def public_reply(token: str, finding_id: int, body: ReplyIn, session: Session = Depends(db.get_session)) -> dict:
    s = _by_token(session, token)
    f = session.get(Finding, finding_id)
    if f is None or f.entity_id != s.entity_id:
        raise HTTPException(404, "issue not found")
    responses = dict(s.responses or {})
    first = str(f.id) not in responses
    responses[str(f.id)] = {"status": body.status, "comment": (body.comment or "").strip()[:2000],
                            "at": datetime.now(timezone.utc).isoformat()}
    s.responses = responses
    entity = session.get(Entity, s.entity_id)
    if first or body.status == "fixed":
        session.add(Alert(org_id=s.org_id, entity_id=s.entity_id, kind="vendor_reply", severity="warning",
                          title=f"{entity.name} replied: {STATUSES[body.status].lower()}",
                          detail=f"{f.title}" + (f". Comment: {body.comment.strip()[:500]}" if body.comment else "")))
    session.commit()
    return responses[str(f.id)]


@router.post("/public/vendor-share/{token}/rescan", status_code=202)
def public_rescan(token: str, tasks: BackgroundTasks, session: Session = Depends(db.get_session)) -> dict:
    from .main import _scan_job
    from .optout import is_opted_out

    s = _by_token(session, token)
    now = datetime.now(timezone.utc)
    if s.last_rescan_at and now - _aware(s.last_rescan_at) < RESCAN_EVERY:
        raise HTTPException(429, "a rescan was requested in the last 6 hours; please try again later")
    entity = session.get(Entity, s.entity_id)
    if is_opted_out(session, entity.primary_domain):
        raise HTTPException(409, "this company has opted out of scanning")
    s.last_rescan_at = now
    session.commit()
    tasks.add_task(_scan_job, entity.id)
    return {"status": "scan started"}
