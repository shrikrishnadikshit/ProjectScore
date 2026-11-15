"""Privacy rights for users of ProjectScore itself (GDPR Art. 15, 17 and 20; India DPDP Act s. 11 and 12).

- Download: everything we hold about the signed-in person, as JSON.
- Delete: the account is erased. Personal details are removed and replaced with a placeholder; records
  other people depend on (for example a scan authorisation the person signed) keep only what is needed
  to show that it happened.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth, db
from .models import (ActiveScan, AdvisoryRequest, ApiKey, CodeReview, Dispute, Questionnaire, SessionToken, User,
                     VendorCertificate, VendorShare)

router = APIRouter(prefix="/api")


def _iso(dt):
    return dt.isoformat() if dt else None


@router.get("/account/export")
def export(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> Response:
    import json

    data = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "profile": {"id": user.id, "email": user.email, "name": user.name, "role": user.role,
                    "organisation": user.org.name, "active": user.active, "created_at": _iso(user.created_at)},
        "sign_in_sessions": [{"created_at": _iso(s.created_at), "expires_at": _iso(s.expires_at)}
                             for s in session.scalars(select(SessionToken).where(SessionToken.user_id == user.id))],
        "api_keys": [{"name": k.name, "prefix": k.prefix, "revoked": k.revoked, "created_at": _iso(k.created_at)}
                     for k in session.scalars(select(ApiKey).where(ApiKey.user_id == user.id))],
        "disputes_submitted": [{"id": d.id, "domain": d.domain, "reason": d.reason}
                               for d in session.scalars(select(Dispute).where(Dispute.submitted_by == user.id))],
        "advisory_requests": [{"id": a.id, "service": a.service, "created_at": _iso(a.created_at)}
                              for a in session.scalars(select(AdvisoryRequest).where(AdvisoryRequest.user_id == user.id))],
        "questionnaires_sent": [{"id": q.id, "recipient_email": q.recipient_email, "created_at": _iso(q.created_at)}
                                for q in session.scalars(select(Questionnaire).where(Questionnaire.created_by == user.id))],
        "vendor_links_shared": [{"id": v.id, "recipient_email": v.recipient_email, "created_at": _iso(v.created_at)}
                                for v in session.scalars(select(VendorShare).where(VendorShare.created_by == user.id))],
        "certificates_recorded": [{"id": c.id, "kind": c.kind, "created_at": _iso(c.created_at)}
                                  for c in session.scalars(select(VendorCertificate).where(VendorCertificate.created_by == user.id))],
        "in_depth_scans_requested": [{"id": a.id, "created_at": _iso(a.created_at)}
                                     for a in session.scalars(select(ActiveScan).where(ActiveScan.requested_by == user.id))],
        "code_reviews_requested": [{"id": r.id, "name": r.name, "created_at": _iso(r.created_at)}
                                   for r in session.scalars(select(CodeReview).where(CodeReview.requested_by == user.id))],
    }
    return Response(json.dumps(data, indent=2), media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="projectscore-my-data.json"'})


class DeleteIn(BaseModel):
    password: str


@router.post("/account/delete", status_code=204)
def delete_account(body: DeleteIn, user: User = Depends(auth.current_user),
                   session: Session = Depends(db.get_session)) -> Response:
    if not auth.verify_password(body.password, user.password_hash):
        raise HTTPException(403, "the password is incorrect")
    if user.role == "owner":
        raise HTTPException(409, "the platform owner account cannot be deleted here")
    if user.role == "admin":
        others = session.scalar(select(func.count()).select_from(User).where(
            User.org_id == user.org_id, User.id != user.id, User.active.is_(True)))
        admins = session.scalar(select(func.count()).select_from(User).where(
            User.org_id == user.org_id, User.id != user.id, User.active.is_(True), User.role == "admin"))
        if others and not admins:
            raise HTTPException(409, "make another member of your organisation an admin before deleting your account")
    for s in session.scalars(select(SessionToken).where(SessionToken.user_id == user.id)).all():
        session.delete(s)
    for k in session.scalars(select(ApiKey).where(ApiKey.user_id == user.id)).all():
        session.delete(k)
    user.email = f"deleted-{user.id}-{secrets.token_hex(4)}@deleted.invalid"
    user.name, user.active = None, False
    user.password_hash = auth.hash_password(secrets.token_urlsafe(32))
    session.commit()
    out = Response(status_code=204)
    out.delete_cookie(auth.COOKIE_NAME, path="/")
    return out
