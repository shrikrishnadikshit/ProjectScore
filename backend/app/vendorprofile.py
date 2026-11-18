"""Vendor details and offboarding (BRS TPRM-001, TPRM-009).

Details: the services the vendor provides, the data it handles, the business owner, the vendor's contact,
contract dates and country. An alert is raised 60 days before a contract ends. Offboarding is a checklist
(access revoked, data returned or deleted, deletion certificate received, accounts and integrations closed,
contract ended); when every item is done the vendor can be removed from monitoring.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Alert, Entity, User, VendorProfile

router = APIRouter(prefix="/api")
FIELDS = ("services", "data_types", "business_owner", "contact_name", "contact_email", "contract_start", "contract_end",
          "country", "spend", "notes")
CHECKLIST = [
    ("access", "All vendor access to our systems revoked (accounts, VPN, API keys, SSO)"),
    ("data", "Our data returned or deleted"),
    ("certificate", "Written deletion certificate received"),
    ("integrations", "Integrations, shared folders and sub-processor links closed"),
    ("contract", "Contract ended and final invoices settled"),
]
NOTICE_DAYS = 60


def _get(session: Session, org_id: int, entity_id: int) -> VendorProfile | None:
    return session.scalars(select(VendorProfile).where(VendorProfile.org_id == org_id, VendorProfile.entity_id == entity_id)).first()


def _out(p: VendorProfile | None) -> dict:
    d = (p.details if p else None) or {}
    ob = (p.offboarding if p else None) or {}
    done = ob.get("done") or {}
    return {"details": {k: d.get(k) for k in FIELDS},
            "offboarding": {"started": bool(ob.get("started_at")), "started_at": ob.get("started_at"),
                            "completed_at": ob.get("completed_at"),
                            "items": [{"key": k, "label": label, "done": bool(done.get(k)), "by": (done.get(k) or {}).get("by"),
                                       "at": (done.get(k) or {}).get("at")} for k, label in CHECKLIST]}}


class ProfileIn(BaseModel):
    details: dict


class ItemIn(BaseModel):
    key: str
    done: bool


@router.get("/entities/{entity_id}/profile")
def get_profile(entity_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    return _out(_get(session, user.org_id, entity_id))


def _row(session: Session, user: User, entity_id: int) -> VendorProfile:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    p = _get(session, user.org_id, entity_id)
    if p is None:
        p = VendorProfile(org_id=user.org_id, entity_id=entity_id, details={}, offboarding={})
        session.add(p)
    return p


@router.put("/entities/{entity_id}/profile")
def set_profile(entity_id: int, body: ProfileIn, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    p = _row(session, user, entity_id)
    clean = {}
    for k in FIELDS:
        v = body.details.get(k)
        if k == "data_types":
            v = [str(x)[:40] for x in v][:15] if isinstance(v, list) else None
        elif v is not None:
            v = str(v).strip()[:1000] or None
        if k in ("contract_start", "contract_end") and v:
            try:
                date.fromisoformat(v)
            except ValueError:
                raise HTTPException(422, f"{k.replace('_', ' ')} must be a date")
        if k == "contact_email" and v and "@" not in v:
            raise HTTPException(422, "not a valid email")
        clean[k] = v
    p.details = clean
    p.contract_end = date.fromisoformat(clean["contract_end"]) if clean.get("contract_end") else None
    p.updated_at = datetime.now(timezone.utc)
    session.commit()
    return _out(p)


@router.post("/entities/{entity_id}/offboarding")
def start_offboarding(entity_id: int, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    p = _row(session, user, entity_id)
    if not (p.offboarding or {}).get("started_at"):
        p.offboarding = {"started_at": datetime.now(timezone.utc).isoformat(), "by": user.name or user.email, "done": {}}
    session.commit()
    return _out(p)


@router.patch("/entities/{entity_id}/offboarding")
def tick(entity_id: int, body: ItemIn, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    p = _row(session, user, entity_id)
    ob = dict(p.offboarding or {})
    if not ob.get("started_at"):
        raise HTTPException(409, "start offboarding first")
    if body.key not in dict(CHECKLIST):
        raise HTTPException(422, "unknown checklist item")
    done = dict(ob.get("done") or {})
    if body.done:
        done[body.key] = {"by": user.name or user.email, "at": datetime.now(timezone.utc).isoformat()}
    else:
        done.pop(body.key, None)
    ob["done"] = done
    ob["completed_at"] = datetime.now(timezone.utc).isoformat() if len(done) == len(CHECKLIST) else None
    p.offboarding = ob
    session.commit()
    return _out(p)


def contract_reminders(session: Session, today: date | None = None) -> int:
    """One alert per contract, 60 days before it ends."""
    today = today or date.today()
    n = 0
    for p in session.scalars(select(VendorProfile).where(VendorProfile.contract_end.is_not(None),
                                                         VendorProfile.contract_end <= today + timedelta(days=NOTICE_DAYS),
                                                         VendorProfile.contract_end >= today)):
        marker = f"contract-{p.contract_end.isoformat()}"
        if (p.offboarding or {}).get("reminded") == marker:
            continue
        name = session.get(Entity, p.entity_id).name
        session.add(Alert(org_id=p.org_id, entity_id=p.entity_id, kind="contract_ending", severity="warning",
                          title=f"{name}: contract ends on {p.contract_end.isoformat()}",
                          detail="Decide whether to renew (reassess first) or offboard the vendor."))
        p.offboarding = {**(p.offboarding or {}), "reminded": marker}
        n += 1
    session.commit()
    return n
