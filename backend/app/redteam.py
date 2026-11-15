"""Red team assessments: managed, authorised attack simulations against an organisation's own systems.

ProjectScore does not run attacks itself. It manages the engagement the way professional red teams
work: the customer sets objectives, scope, permitted techniques, a testing window and an emergency
contact, and signs a written authorisation for domains it has proved it controls. The red team (the
platform owner's team or a partner) records progress and findings; the customer can pause testing at any
time, sees every finding with its ATT&CK technique and fix, marks fixes, and asks for retests.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .attack import T
from .models import Alert, DomainVerification, Organization, RedTeamEngagement, RedTeamFinding, RedTeamLog, User

router = APIRouter(prefix="/api")

STATUSES = ["requested", "scoping", "approved", "in_progress", "reporting", "retesting", "closed", "cancelled"]
TECHNIQUES = {
    "external_network": "External network and perimeter testing",
    "web_application": "Web application and API testing",
    "phishing": "Phishing simulation against named staff",
    "credential_attacks": "Password spraying against internet-facing logins (rate-limited)",
    "cloud": "Cloud configuration and identity testing",
    "assumed_breach": "Assumed breach: start from a provided internal account or device",
    "social_engineering": "Phone and in-person social engineering",
    "physical": "Physical access testing of named sites",
}
STAGES = ["Reconnaissance", "Resource development", "Initial access", "Execution", "Persistence", "Privilege escalation",
          "Defense evasion", "Credential access", "Discovery", "Lateral movement", "Collection", "Command and control",
          "Exfiltration", "Impact"]
SEVERITIES = ["critical", "high", "medium", "low", "info"]
FINDING_STATUS = ["open", "fix_claimed", "retest_passed", "retest_failed", "risk_accepted"]
VERIFICATION_VALID_DAYS = 90
AUTHORISATION = (
    "I, {name} ({title}), confirm that I am authorised to approve this red team assessment on behalf of {org}. "
    "I authorise ProjectScore and the testers it assigns to simulate attacks against the systems in scope "
    "({scope}) between {start} and {end}, using only these techniques: {techniques}. Systems listed as "
    "exclusions must not be tested. Testing will stop immediately if I or the emergency contact ask, or if the "
    "pause button is pressed. I confirm that {org} owns these systems or has the written permission of their "
    "owners and hosting providers, and that relevant staff and providers have been informed as needed."
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt):
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _is_operator(user: User) -> bool:
    return user.role == "owner"


def _log(session: Session, e: RedTeamEngagement, kind: str, text: str, actor: str | None) -> None:
    session.add(RedTeamLog(engagement_id=e.id, kind=kind, text=text[:4000], actor=actor))


def _notify(session: Session, org_id: int, e: RedTeamEngagement, title: str, detail: str = "") -> None:
    session.add(Alert(org_id=org_id, entity_id=None, kind="red_team", severity="warning", title=title[:300], detail=detail[:4000]))


def _operator_orgs(session: Session) -> list[int]:
    return list({u.org_id for u in session.scalars(select(User).where(User.role == "owner", User.active.is_(True)))})


def _finding_out(f: RedTeamFinding) -> dict:
    return {"id": f.id, "title": f.title, "severity": f.severity, "stage": f.stage, "asset": f.asset,
            "techniques": [{"id": t, "name": T.get(t, t), "url": f"https://attack.mitre.org/techniques/{t.replace('.', '/')}/"}
                           for t in f.techniques or []],
            "description": f.description, "evidence": f.evidence, "recommendation": f.recommendation,
            "status": f.status, "customer_note": f.customer_note,
            "created_at": _aware(f.created_at).isoformat(), "updated_at": _aware(f.updated_at).isoformat()}


def _out(session: Session, e: RedTeamEngagement, detail: bool = False) -> dict:
    findings = session.scalars(select(RedTeamFinding).where(RedTeamFinding.engagement_id == e.id)).all()
    org = session.get(Organization, e.org_id)
    out = {"id": e.id, "name": e.name, "organisation": org.name if org else None, "status": e.status, "paused": e.paused,
           "window_start": e.window_start.isoformat() if e.window_start else None,
           "window_end": e.window_end.isoformat() if e.window_end else None,
           "created_at": _aware(e.created_at).isoformat(), "updated_at": _aware(e.updated_at).isoformat(),
           "finding_counts": {s: sum(f.severity == s for f in findings) for s in SEVERITIES},
           "open_findings": sum(f.status in ("open", "retest_failed") for f in findings)}
    if detail:
        logs = session.scalars(select(RedTeamLog).where(RedTeamLog.engagement_id == e.id)
                               .order_by(RedTeamLog.created_at.desc(), RedTeamLog.id.desc())).all()
        out.update({"objectives": e.objectives, "scope": e.scope, "techniques": [{"key": t, "label": TECHNIQUES.get(t, t)} for t in e.techniques],
                    "testing_hours": e.testing_hours, "emergency_contact": e.emergency_contact,
                    "authoriser_name": e.authoriser_name, "authoriser_title": e.authoriser_title,
                    "authorisation_text": e.authorisation_text, "summary": e.summary,
                    "findings": [_finding_out(f) for f in sorted(findings, key=lambda f: (SEVERITIES.index(f.severity), f.id))],
                    "log": [{"kind": l.kind, "text": l.text, "actor": l.actor, "at": _aware(l.created_at).isoformat()} for l in logs]})
    return out


def _get(session: Session, user: User, eid: int) -> RedTeamEngagement:
    e = session.get(RedTeamEngagement, eid)
    if e is None or (e.org_id != user.org_id and not _is_operator(user)):
        raise HTTPException(404, "engagement not found")
    return e


@router.get("/red-team/config")
def config(user: User = Depends(auth.current_user)) -> dict:
    return {"techniques": TECHNIQUES, "stages": STAGES, "statuses": STATUSES, "finding_statuses": FINDING_STATUS,
            "authorisation_template": AUTHORISATION, "is_operator": _is_operator(user)}


class EngagementIn(BaseModel):
    name: str
    objectives: str
    domains: list[str]
    ip_ranges: list[str] = []
    exclusions: str | None = None
    techniques: list[str]
    window_start: date
    window_end: date
    testing_hours: str | None = None
    emergency_name: str
    emergency_phone: str
    emergency_email: str
    authoriser_name: str
    authoriser_title: str
    confirm: bool = False

    @field_validator("name", "objectives", "emergency_name", "emergency_phone", "emergency_email", "authoriser_name", "authoriser_title")
    @classmethod
    def _required(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("this field is required")
        return v

    @field_validator("techniques")
    @classmethod
    def _tech(cls, v):
        v = [t for t in dict.fromkeys(v) if t in TECHNIQUES]
        if not v:
            raise ValueError("choose at least one permitted technique")
        return v

    @field_validator("ip_ranges")
    @classmethod
    def _ips(cls, v):
        import ipaddress

        out = []
        for r in v:
            r = r.strip()
            if not r:
                continue
            net = ipaddress.ip_network(r, strict=False)
            if not net.is_global:
                raise ValueError(f"{r} is not a public address range")
            if net.num_addresses > 65536:
                raise ValueError(f"{r} is too large; list ranges of /16 or smaller")
            out.append(str(net))
        return out


@router.post("/red-team", status_code=201)
def request_engagement(body: EngagementIn, request: Request, user: User = Depends(auth.require_admin),
                       session: Session = Depends(db.get_session)) -> dict:
    if not body.confirm:
        raise HTTPException(422, "please confirm the authorisation statement")
    today = date.today()
    if body.window_end < body.window_start or body.window_start < today - timedelta(days=1):
        raise HTTPException(422, "choose a testing window that starts today or later and ends after it starts")
    if (body.window_end - body.window_start).days > 120:
        raise HTTPException(422, "a testing window can be at most 120 days")
    domains = sorted({d.strip().lower() for d in body.domains if d.strip()})
    if not domains:
        raise HTTPException(422, "add at least one domain")
    cutoff = _now() - timedelta(days=VERIFICATION_VALID_DAYS)
    verified = {v.domain for v in session.scalars(select(DomainVerification).where(DomainVerification.org_id == user.org_id))
                if v.verified_at and _aware(v.verified_at) > cutoff}
    unverified = [d for d in domains if d not in verified and not any(d.endswith("." + v) for v in verified)]
    if unverified:
        raise HTTPException(422, f"prove you control these domains first (In-depth scans page, step 1): {', '.join(unverified)}")
    scope_text = ", ".join(domains + body.ip_ranges)
    text = AUTHORISATION.format(name=body.authoriser_name, title=body.authoriser_title, org=user.org.name, scope=scope_text,
                                start=body.window_start.isoformat(), end=body.window_end.isoformat(),
                                techniques="; ".join(TECHNIQUES[t] for t in body.techniques))
    e = RedTeamEngagement(org_id=user.org_id, name=body.name[:200], objectives=body.objectives[:4000],
                          scope={"domains": domains, "ip_ranges": body.ip_ranges, "exclusions": (body.exclusions or "")[:2000]},
                          techniques=body.techniques, window_start=body.window_start, window_end=body.window_end,
                          testing_hours=(body.testing_hours or "")[:200] or None,
                          emergency_contact={"name": body.emergency_name[:200], "phone": body.emergency_phone[:50],
                                             "email": body.emergency_email[:200]},
                          authoriser_name=body.authoriser_name[:255], authoriser_title=body.authoriser_title[:255],
                          authorisation_text=text, authorised_from_ip=request.client.host if request.client else None,
                          requested_by=user.id)
    session.add(e)
    session.flush()
    _log(session, e, "status", "Engagement requested and authorisation signed", user.email)
    for org_id in _operator_orgs(session):
        _notify(session, org_id, e, f"New red team request from {user.org.name}: {e.name}")
    session.commit()
    return _out(session, e, detail=True)


@router.get("/red-team")
def list_engagements(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> list[dict]:
    q = select(RedTeamEngagement).order_by(RedTeamEngagement.created_at.desc())
    if not _is_operator(user):
        q = q.where(RedTeamEngagement.org_id == user.org_id)
    return [_out(session, e) for e in session.scalars(q).all()]


@router.get("/red-team/{eid}")
def get_engagement(eid: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    return _out(session, _get(session, user, eid), detail=True)


class PauseIn(BaseModel):
    paused: bool
    reason: str | None = None


@router.post("/red-team/{eid}/pause")
def pause(eid: int, body: PauseIn, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    """The customer's stop button (any member of the customer organisation can press it)."""
    e = _get(session, user, eid)
    if e.status in ("closed", "cancelled"):
        raise HTTPException(409, "this engagement has ended")
    e.paused, e.updated_at = body.paused, _now()
    reason = (body.reason or "").strip()
    _log(session, e, "pause" if body.paused else "resume",
         ("Testing PAUSED" if body.paused else "Testing resumed") + (f": {reason}" if reason else ""), user.email)
    targets = _operator_orgs(session) if e.org_id == user.org_id else [e.org_id]
    for org_id in targets:
        _notify(session, org_id, e, f"Red team {'PAUSED' if body.paused else 'resumed'}: {e.name}", reason)
    session.commit()
    return _out(session, e, detail=True)


class CancelIn(BaseModel):
    reason: str | None = None


@router.post("/red-team/{eid}/cancel")
def cancel(eid: int, body: CancelIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    e = _get(session, user, eid)
    if e.status in ("closed", "cancelled"):
        raise HTTPException(409, "this engagement has ended")
    e.status, e.paused, e.updated_at = "cancelled", True, _now()
    _log(session, e, "status", "Engagement cancelled; authorisation withdrawn" + (f": {body.reason}" if body.reason else ""), user.email)
    for org_id in _operator_orgs(session) if e.org_id == user.org_id else [e.org_id]:
        _notify(session, org_id, e, f"Red team cancelled: {e.name}", body.reason or "")
    session.commit()
    return _out(session, e, detail=True)


class FindingStatusIn(BaseModel):
    status: str
    note: str | None = None

    @field_validator("status")
    @classmethod
    def _s(cls, v):
        if v not in FINDING_STATUS:
            raise ValueError("unknown status")
        return v


@router.post("/red-team/{eid}/findings/{fid}/status")
def finding_status(eid: int, fid: int, body: FindingStatusIn, user: User = Depends(auth.current_user),
                   session: Session = Depends(db.get_session)) -> dict:
    e = _get(session, user, eid)
    f = session.get(RedTeamFinding, fid)
    if f is None or f.engagement_id != e.id:
        raise HTTPException(404, "finding not found")
    customer_allowed = {"fix_claimed", "risk_accepted", "open"}
    if not _is_operator(user) and body.status not in customer_allowed:
        raise HTTPException(403, "only the red team can record retest results")
    f.status, f.updated_at = body.status, _now()
    if body.note:
        f.customer_note = body.note.strip()[:2000]
    label = {"fix_claimed": "marked as fixed; retest requested", "risk_accepted": "risk accepted", "open": "reopened",
             "retest_passed": "retest passed", "retest_failed": "retest failed"}[body.status]
    _log(session, e, "finding", f"{f.title}: {label}" + (f" ({body.note.strip()[:300]})" if body.note else ""), user.email)
    if body.status == "fix_claimed":
        if e.status in ("reporting", "closed"):
            e.status = "retesting"
        for org_id in _operator_orgs(session):
            _notify(session, org_id, e, f"Retest requested on {e.name}: {f.title}")
    elif body.status in ("retest_passed", "retest_failed"):
        _notify(session, e.org_id, e, f"Red team retest {'passed' if body.status == 'retest_passed' else 'failed'}: {f.title}")
    e.updated_at = _now()
    session.commit()
    return _out(session, e, detail=True)


# ---------- red team operator (platform owner) ----------

def _operator(user: User = Depends(auth.current_user)) -> User:
    if not _is_operator(user):
        raise HTTPException(403, "red team operators only")
    return user


class UpdateIn(BaseModel):
    status: str | None = None
    summary: str | None = None
    note: str | None = None

    @field_validator("status")
    @classmethod
    def _s(cls, v):
        if v is not None and v not in STATUSES:
            raise ValueError("unknown status")
        return v


@router.post("/red-team/{eid}/update")
def operator_update(eid: int, body: UpdateIn, user: User = Depends(_operator), session: Session = Depends(db.get_session)) -> dict:
    e = _get(session, user, eid)
    if body.status and body.status != e.status:
        if body.status == "in_progress":
            if e.paused:
                raise HTTPException(409, "the customer has paused testing; it cannot start until they resume it")
            if e.window_end and date.today() > e.window_end:
                raise HTTPException(409, "the authorised testing window has ended; ask the customer for a new one")
            if e.window_start and date.today() < e.window_start:
                raise HTTPException(409, "the authorised testing window has not started yet")
        e.status = body.status
        _log(session, e, "status", f"Status: {body.status.replace('_', ' ')}", user.email)
        _notify(session, e.org_id, e, f"Red team {e.name}: {body.status.replace('_', ' ')}")
    if body.summary is not None:
        e.summary = body.summary.strip()[:8000] or None
    if body.note:
        _log(session, e, "activity", body.note.strip(), user.email)
    e.updated_at = _now()
    session.commit()
    return _out(session, e, detail=True)


class FindingIn(BaseModel):
    title: str
    severity: str
    stage: str | None = None
    techniques: list[str] = []
    asset: str | None = None
    description: str
    evidence: str | None = None
    recommendation: str

    @field_validator("severity")
    @classmethod
    def _sev(cls, v):
        if v not in SEVERITIES:
            raise ValueError("unknown severity")
        return v

    @field_validator("stage")
    @classmethod
    def _stage(cls, v):
        if v and v not in STAGES:
            raise ValueError("unknown stage")
        return v or None

    @field_validator("techniques")
    @classmethod
    def _techs(cls, v):
        import re

        out = [t.strip().upper() for t in v if t.strip()]
        bad = [t for t in out if not re.fullmatch(r"T\d{4}(\.\d{3})?", t)]
        if bad:
            raise ValueError(f"not an ATT&CK technique id: {', '.join(bad)}")
        return out[:10]


@router.post("/red-team/{eid}/findings", status_code=201)
def add_finding(eid: int, body: FindingIn, user: User = Depends(_operator), session: Session = Depends(db.get_session)) -> dict:
    e = _get(session, user, eid)
    f = RedTeamFinding(engagement_id=e.id, title=body.title.strip()[:300], severity=body.severity, stage=body.stage,
                       techniques=body.techniques, asset=(body.asset or "").strip()[:300] or None,
                       description=body.description.strip()[:8000], evidence=(body.evidence or "").strip()[:8000] or None,
                       recommendation=body.recommendation.strip()[:4000])
    session.add(f)
    session.flush()
    _log(session, e, "finding", f"New {f.severity} finding: {f.title}", user.email)
    if f.severity in ("critical", "high"):
        _notify(session, e.org_id, e, f"Red team found a {f.severity} issue: {f.title}", f.recommendation)
    e.updated_at = _now()
    session.commit()
    return _out(session, e, detail=True)
