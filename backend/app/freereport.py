"""Free one-time rating summary for prospects (lead generation).

Someone enters their work email and their company's domain on the public /free-report page. The email
must be at that domain, so people ask about their own organisation. The summary shows the score, grade,
factor grades and how many issues of each severity were found, but no hostnames or IP addresses: the
detail is for customers. Every request is stored as a lead that the owner sees on the Leads page.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db
from .models import Entity, Finding, FreeReport, Score, User
from .optout import OptOutIn, _IpLimiter, is_opted_out, require_owner
from .scan import NothingAssessed, OptedOut, scan_entity

logger = logging.getLogger("projectscore.freereport")
router = APIRouter(prefix="/api")

limiter = _IpLimiter(limit=3, window=24 * 3600)
# Overall cap on new scans started from the public page, whatever addresses requests claim to come from.
daily_scans = _IpLimiter(limit=int(os.environ.get("FREE_REPORT_DAILY_SCANS", "40")), window=24 * 3600)
FRESH = timedelta(days=7)  # reuse a rating this recent instead of scanning again
EXPIRES = timedelta(days=30)
SEVERITIES = ("critical", "high", "medium", "low")


class FreeReportIn(OptOutIn):
    name: str | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str | None) -> str | None:
        return (v or "").strip()[:255] or None


def _email_matches(email: str, domain: str) -> bool:
    host = email.rsplit("@", 1)[1].lower()
    return host == domain or host.endswith("." + domain) or domain.endswith("." + host)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _latest(session: Session, entity_id: int) -> Score | None:
    return session.scalars(select(Score).where(Score.entity_id == entity_id)
                           .order_by(Score.created_at.desc(), Score.id.desc())).first()


def _job(report_id: int) -> None:
    session = db.SessionLocal()
    try:
        report = session.get(FreeReport, report_id)
        try:
            scan_entity(session, session.get(Entity, report.entity_id))
            report.status = "ready"
        except OptedOut:
            report.status, report.message = "failed", "this domain has opted out of scanning"
        except NothingAssessed:
            report.status, report.message = "failed", "we could not reach this domain; check the spelling"
        except Exception:
            logger.exception("free report scan failed for %s", report.domain)
            report.status, report.message = "failed", "the scan failed; please try again later"
        session.commit()
    finally:
        session.close()


@router.post("/public/free-report", status_code=202)
def request_report(body: FreeReportIn, request: Request, tasks: BackgroundTasks,
                   session: Session = Depends(db.get_session)) -> dict:
    if body.website:
        return {"token": secrets.token_urlsafe(24)}  # bots get a token that leads nowhere
    if not _email_matches(body.contact_email, body.domain):
        raise HTTPException(422, f"please use your work email at {body.domain}; the free report is for your own organisation")
    if is_opted_out(session, body.domain):
        raise HTTPException(409, "this domain has opted out of scanning")
    from .privacy import suppressed

    if suppressed(session, body.contact_email):
        raise HTTPException(409, "this email address asked us not to store or use it; please use another address")
    client = request.headers.get("x-forwarded-for", request.client.host if request.client else "?").split(",")[0]
    if not limiter.allow(client.strip()):
        raise HTTPException(429, "you have requested several reports today; please try again tomorrow")

    entity = session.scalars(select(Entity).where(Entity.primary_domain == body.domain)).first()
    if entity is None:
        entity = Entity(name=body.organisation or body.domain, primary_domain=body.domain)
        session.add(entity)
        session.flush()
    latest = _latest(session, entity.id)
    fresh = latest is not None and datetime.now(timezone.utc) - _aware(latest.created_at) < FRESH
    if not fresh and not daily_scans.allow("all"):
        session.rollback()
        raise HTTPException(429, "we are handling a lot of requests today; please try again tomorrow")
    report = FreeReport(token=secrets.token_urlsafe(24), domain=body.domain, contact_email=body.contact_email,
                        name=body.name, organisation=body.organisation, entity_id=entity.id,
                        status="ready" if fresh else "scanning")
    session.add(report)
    session.commit()
    if not fresh:
        tasks.add_task(_job, report.id)
    return {"token": report.token}


@router.get("/public/free-report/{token}")
def get_report(token: str, session: Session = Depends(db.get_session)) -> dict:
    report = session.scalars(select(FreeReport).where(FreeReport.token == token)).first()
    if report is None or datetime.now(timezone.utc) - _aware(report.created_at) > EXPIRES:
        raise HTTPException(404, "report not found or expired")
    out = {"domain": report.domain, "status": report.status, "message": report.message}
    if report.status != "ready" or report.entity_id is None:
        return out
    latest = _latest(session, report.entity_id)
    if latest is None:
        return {**out, "status": "failed", "message": "no rating is available for this domain"}
    findings = session.scalars(select(Finding).where(Finding.entity_id == report.entity_id,
                                                     Finding.status == "open")).all()
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    issues = sorted({(f.severity, f.title) for f in findings if f.severity in ("critical", "high", "medium")},
                    key=lambda x: SEVERITIES.index(x[0]))
    return {**out, "score": latest.overall, "grade": latest.grade, "rated_at": _aware(latest.created_at).isoformat(),
            "coverage": (latest.trace or {}).get("coverage"),
            "factors": {k: {"grade": v["grade"], "score": round(v["score"])} for k, v in (latest.factors or {}).items()},
            "counts": counts,
            "top_issues": [{"severity": s, "title": t} for s, t in issues[:5]]}


@router.get("/free-reports")
def list_leads(_: User = Depends(require_owner), session: Session = Depends(db.get_session)) -> list[dict]:
    rows = session.scalars(select(FreeReport).order_by(FreeReport.created_at.desc())).all()
    out = []
    for r in rows:
        latest = _latest(session, r.entity_id) if r.entity_id else None
        out.append({"id": r.id, "domain": r.domain, "contact_email": r.contact_email, "name": r.name,
                    "organisation": r.organisation, "status": r.status, "entity_id": r.entity_id,
                    "score": latest.overall if latest else None, "grade": latest.grade if latest else None,
                    "created_at": _aware(r.created_at).isoformat()})
    return out
