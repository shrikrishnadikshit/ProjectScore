"""Vendor certificates and audit reports (ISO 27001, SOC 2, PCI DSS...), with expiry reminders.

Customers record what each vendor has shown them. We track expiry, remind 30 days before, and set the
claims against what our scans see: a vendor whose ISO 27001 covers vulnerability management but who has
actively exploited software on the internet is worth a conversation.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Alert, Entity, Finding, PortfolioItem, User, VendorCertificate

router = APIRouter(prefix="/api")
KINDS = {
    "iso27001": "ISO/IEC 27001", "iso27701": "ISO/IEC 27701 (privacy)", "iso22301": "ISO 22301 (continuity)",
    "soc2_type2": "SOC 2 Type II", "soc2_type1": "SOC 2 Type I", "pci_dss": "PCI DSS",
    "cert_in_audit": "CERT-In empanelled audit", "rbi_audit": "RBI / SEBI cyber audit", "other": "Other",
}
REMIND_DAYS = 30
# Risk factors that contradict a clean certificate when our scans show serious issues in them.
CONTRADICTS = {"vulnerability", "network_exposure", "compromise"}


def status(c: VendorCertificate, today: date | None = None) -> str:
    today = today or date.today()
    if c.expires_on is None:
        return "no_expiry"
    if c.expires_on < today:
        return "expired"
    return "expiring" if (c.expires_on - today).days <= REMIND_DAYS * 2 else "valid"


def _out(c: VendorCertificate, entity_name: str | None = None) -> dict:
    return {"id": c.id, "entity_id": c.entity_id, "entity": entity_name, "kind": c.kind, "kind_label": KINDS.get(c.kind, c.kind),
            "reference": c.reference, "issuer": c.issuer, "scope": c.scope,
            "issued_on": c.issued_on.isoformat() if c.issued_on else None,
            "expires_on": c.expires_on.isoformat() if c.expires_on else None,
            "days_left": (c.expires_on - date.today()).days if c.expires_on else None,
            "exceptions": c.exceptions, "note": c.note, "status": status(c)}


class CertIn(BaseModel):
    kind: str
    reference: str | None = None
    issuer: str | None = None
    scope: str | None = None
    issued_on: date | None = None
    expires_on: date | None = None
    exceptions: int | None = None
    note: str | None = None

    @field_validator("kind")
    @classmethod
    def _kind(cls, v):
        if v not in KINDS:
            raise ValueError("unknown certificate type")
        return v

    @field_validator("exceptions")
    @classmethod
    def _exc(cls, v):
        if v is not None and not 0 <= v <= 10000:
            raise ValueError("exceptions must be 0 or more")
        return v


def _apply(c: VendorCertificate, body: CertIn) -> None:
    if body.issued_on and body.expires_on and body.expires_on < body.issued_on:
        raise HTTPException(422, "the expiry date is before the issue date")
    c.kind = body.kind
    c.reference, c.issuer = (body.reference or "").strip()[:200] or None, (body.issuer or "").strip()[:200] or None
    c.scope, c.note = (body.scope or "").strip()[:1000] or None, (body.note or "").strip()[:2000] or None
    c.issued_on, c.expires_on, c.exceptions = body.issued_on, body.expires_on, body.exceptions
    c.reminded_at = None


@router.get("/entities/{entity_id}/certificates")
def list_certs(entity_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    rows = session.scalars(select(VendorCertificate).where(VendorCertificate.org_id == user.org_id,
                                                           VendorCertificate.entity_id == entity_id)
                           .order_by(VendorCertificate.expires_on)).all()
    serious = session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open",
                                                    Finding.severity.in_(("critical", "high")),
                                                    Finding.risk_factor.in_(CONTRADICTS))).all()
    valid = [c for c in rows if status(c) != "expired" and c.kind in ("iso27001", "soc2_type2", "pci_dss")]
    warnings = []
    if valid and serious:
        warnings.append(f"{len(valid)} valid certificate(s) on record, but our scans show {len(serious)} serious "
                        f"issue(s) in vulnerability management, network exposure or compromise. Ask the vendor "
                        f"whether these systems are in the certified scope.")
    return {"kinds": KINDS, "certificates": [_out(c) for c in rows], "warnings": warnings}


@router.post("/entities/{entity_id}/certificates", status_code=201)
def add_cert(entity_id: int, body: CertIn, user: User = Depends(auth.current_user),
             session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    c = VendorCertificate(org_id=user.org_id, entity_id=entity_id, created_by=user.id)
    _apply(c, body)
    session.add(c)
    session.commit()
    return _out(c)


def _own(session: Session, user: User, cert_id: int) -> VendorCertificate:
    c = session.get(VendorCertificate, cert_id)
    if c is None or c.org_id != user.org_id:
        raise HTTPException(404, "certificate not found")
    return c


@router.put("/certificates/{cert_id}")
def update_cert(cert_id: int, body: CertIn, user: User = Depends(auth.current_user),
                session: Session = Depends(db.get_session)) -> dict:
    c = _own(session, user, cert_id)
    _apply(c, body)
    session.commit()
    return _out(c)


@router.delete("/certificates/{cert_id}", status_code=204)
def delete_cert(cert_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> None:
    session.delete(_own(session, user, cert_id))
    session.commit()


@router.get("/certificates")
def portfolio_certs(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    names = {i.entity_id: i.entity.name for i in session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id))}
    rows = session.scalars(select(VendorCertificate).where(VendorCertificate.org_id == user.org_id)
                           .order_by(VendorCertificate.expires_on)).all()
    certs = [_out(c, names.get(c.entity_id)) for c in rows if c.entity_id in names]
    return {"certificates": certs, "without_any": sorted(n for i, n in names.items() if i not in {c.entity_id for c in rows}),
            "expired": sum(c["status"] == "expired" for c in certs), "expiring": sum(c["status"] == "expiring" for c in certs)}


def send_reminders(session: Session, today: date | None = None) -> int:
    """In-app alerts for certificates expiring within 30 days or already expired; once per certificate."""
    today = today or date.today()
    rows = session.scalars(select(VendorCertificate).where(VendorCertificate.reminded_at.is_(None),
                                                           VendorCertificate.expires_on.is_not(None),
                                                           VendorCertificate.expires_on <= today + timedelta(days=REMIND_DAYS))).all()
    for c in rows:
        entity = session.get(Entity, c.entity_id)
        days = (c.expires_on - today).days
        when = f"expired on {c.expires_on:%d %b %Y}" if days < 0 else f"expires in {days} days ({c.expires_on:%d %b %Y})"
        session.add(Alert(org_id=c.org_id, entity_id=c.entity_id, kind="certificate", severity="warning",
                          title=f"{entity.name if entity else 'Vendor'}: {KINDS.get(c.kind, c.kind)} {when}",
                          detail="Ask the vendor for the renewed certificate or latest audit report."))
        c.reminded_at = datetime.now(timezone.utc)
    session.commit()
    return len(rows)
