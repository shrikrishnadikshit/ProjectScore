"""Public scanner information and opt-out requests (BRS 4.4: identifiable scanning with an opt-out).

Anyone can submit a request without signing in. The platform owner reviews it; approved domains
(and their subdomains) are excluded from all scanning.
"""

import re
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import OptOutRequest, User

router = APIRouter(prefix="/api")

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")


def is_opted_out(session: Session, domain: str) -> bool:
    approved = session.scalars(select(OptOutRequest.domain).where(OptOutRequest.status == "approved")).all()
    domain = domain.lower()
    return any(domain == d or domain.endswith("." + d) for d in approved)


class _IpLimiter:
    def __init__(self, limit: int = 5, window: int = 3600):
        self.limit, self.window, self.hits = limit, window, {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        recent = [t for t in self.hits.get(key, []) if now - t < self.window]
        if len(recent) >= self.limit:
            self.hits[key] = recent
            return False
        self.hits[key] = recent + [now]
        return True


limiter = _IpLimiter()
# Overall cap on the public forms, in case per-IP limits are dodged by spoofing forwarded addresses.
public_daily = _IpLimiter(limit=200, window=24 * 3600)


class OptOutIn(BaseModel):
    domain: str
    contact_email: str
    organisation: str | None = None
    reason: str | None = None
    website: str | None = None  # honeypot: humans never see or fill this field

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        v = v.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].removeprefix("www.")
        if not _DOMAIN_RE.match(v):
            raise ValueError("not a valid domain")
        return v

    @field_validator("contact_email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip()
        if not _EMAIL_RE.match(v):
            raise ValueError("not a valid email")
        return v

    @field_validator("organisation", "reason")
    @classmethod
    def _trim(cls, v: str | None) -> str | None:
        return v.strip()[:2000] if v else None


def _out(r: OptOutRequest) -> dict:
    return {"id": r.id, "domain": r.domain, "contact_email": r.contact_email, "organisation": r.organisation,
            "reason": r.reason, "status": r.status, "created_at": r.created_at.isoformat(),
            "decided_at": r.decided_at.isoformat() if r.decided_at else None}


@router.post("/public/opt-out", status_code=202)
def request_opt_out(body: OptOutIn, request: Request, session: Session = Depends(db.get_session)) -> dict:
    if body.website:
        return {"status": "received"}
    client = request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0]
    if not limiter.allow(client.strip()) or not public_daily.allow("all"):
        raise HTTPException(429, "too many requests; please try again later")
    session.add(OptOutRequest(domain=body.domain, contact_email=body.contact_email,
                              organisation=body.organisation, reason=body.reason))
    session.commit()
    return {"status": "received"}


def require_owner(user: User = Depends(auth.current_user)) -> User:
    if user.role != "owner":
        raise HTTPException(403, "owner only")
    return user


@router.get("/opt-outs")
def list_opt_outs(_: User = Depends(require_owner), session: Session = Depends(db.get_session)) -> list[dict]:
    rows = session.scalars(select(OptOutRequest).order_by(OptOutRequest.created_at.desc())).all()
    return [_out(r) for r in rows]


class DecisionIn(BaseModel):
    status: str


@router.post("/opt-outs/{request_id}")
def decide_opt_out(request_id: int, body: DecisionIn, _: User = Depends(require_owner),
                   session: Session = Depends(db.get_session)) -> dict:
    if body.status not in ("approved", "rejected", "pending"):
        raise HTTPException(422, "status must be approved, rejected or pending")
    row = session.get(OptOutRequest, request_id)
    if row is None:
        raise HTTPException(404, "request not found")
    row.status = body.status
    row.decided_at = datetime.now(timezone.utc) if body.status != "pending" else None
    session.commit()
    return _out(row)
