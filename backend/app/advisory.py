"""Advisory and remediation help: customers ask the platform team for expert help, the owner manages it.

Customers see their own organisation's requests and the owner's replies. The owner sees all requests on
the Advisory page, can update their status and reply, and can see the company's fix plan for context.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import AdvisoryRequest, Entity, Organization, User
from .optout import require_owner

router = APIRouter(prefix="/api")

SERVICES = {
    "fix_guidance": "Expert call to explain findings and agree a fix plan",
    "remediation_support": "Hands-on help fixing the issues",
    "vendor_followup": "Follow up with this vendor on our behalf",
    "assessment": "Deeper security assessment (in-depth scan or audit)",
}
STATUSES = ("new", "in_progress", "done", "declined")


def _out(session: Session, r: AdvisoryRequest) -> dict:
    entity = session.get(Entity, r.entity_id) if r.entity_id else None
    user = session.get(User, r.user_id) if r.user_id else None
    org = session.get(Organization, r.org_id)
    return {"id": r.id, "service": r.service, "service_label": SERVICES.get(r.service, r.service),
            "finding_codes": r.finding_codes or [], "message": r.message, "preferred_contact": r.preferred_contact,
            "status": r.status, "owner_note": r.owner_note, "created_at": r.created_at.isoformat(),
            "entity": {"id": entity.id, "name": entity.name} if entity else None,
            "requested_by": user.email if user else None, "organisation": org.name if org else None}


class AdvisoryIn(BaseModel):
    service: str
    finding_codes: list[str] = []
    message: str | None = None
    preferred_contact: str | None = None

    @field_validator("service")
    @classmethod
    def _service(cls, v):
        if v not in SERVICES:
            raise ValueError("choose a service from the list")
        return v


@router.get("/advisory/services")
def services() -> list[dict]:
    return [{"id": k, "label": v} for k, v in SERVICES.items()]


@router.post("/entities/{entity_id}/advisory", status_code=201)
def request_help(entity_id: int, body: AdvisoryIn, user: User = Depends(auth.current_user),
                 session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    r = AdvisoryRequest(org_id=user.org_id, entity_id=entity_id, user_id=user.id, service=body.service,
                        finding_codes=[c[:100] for c in body.finding_codes[:50]],
                        message=(body.message or "").strip()[:4000] or None,
                        preferred_contact=(body.preferred_contact or "").strip()[:200] or None)
    session.add(r)
    session.commit()
    return _out(session, r)


@router.get("/advisory")
def list_requests(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> list[dict]:
    q = select(AdvisoryRequest).order_by(AdvisoryRequest.status != "new", AdvisoryRequest.created_at.desc())
    if user.role != "owner":
        q = q.where(AdvisoryRequest.org_id == user.org_id)
    return [_out(session, r) for r in session.scalars(q).all()]


class UpdateIn(BaseModel):
    status: str
    owner_note: str | None = None

    @field_validator("status")
    @classmethod
    def _status(cls, v):
        if v not in STATUSES:
            raise ValueError("unknown status")
        return v


@router.post("/advisory/{request_id}")
def update_request(request_id: int, body: UpdateIn, _: User = Depends(require_owner),
                   session: Session = Depends(db.get_session)) -> dict:
    r = session.get(AdvisoryRequest, request_id)
    if r is None:
        raise HTTPException(404, "request not found")
    r.status, r.owner_note = body.status, (body.owner_note or "").strip()[:4000] or None
    session.commit()
    return _out(session, r)
