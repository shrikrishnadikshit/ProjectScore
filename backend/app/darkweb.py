"""Dark web view: ransomware leak-site listings and infostealer logs for one company and the portfolio."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .collectors import darkweb as feeds
from .models import Finding, PortfolioItem, User

router = APIRouter(prefix="/api")


def _dark(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.status == "open" and (f.code.startswith(("ransomware_leak_", "infostealer_"))
                                                            or (f.evidence or {}).get("darkweb"))]


def summary(findings: list[Finding]) -> dict:
    dark = _dark(findings)
    leaks = [{"id": f.id, "title": f.title, "severity": f.severity, **{k: (f.evidence or {}).get(k) for k in
             ("group", "event_date", "victim", "link", "matched_on")}} for f in dark if f.code.startswith("ransomware_leak_")]
    emp = next((f for f in dark if f.code == "infostealer_employees"), None)
    cust = next((f for f in dark if f.code == "infostealer_customers"), None)
    ev = (emp.evidence or {}) if emp else {}
    level = ("critical" if any(l["severity"] == "critical" for l in leaks) else "high" if leaks or (emp and emp.severity == "high")
             else "medium" if emp and emp.severity == "medium" else "low")
    return {"level": level, "leak_sites": leaks,
            "infostealers": {"employees": ev.get("employees", 0), "last_employee": ev.get("last_employee"),
                             "families": ev.get("families", []), "employee_logins": ev.get("employee_logins", []),
                             "severity": emp.severity if emp else None,
                             "users": ((cust.evidence or {}).get("users", 0) if cust else 0),
                             "last_user": ((cust.evidence or {}).get("last_user") if cust else None)},
            "sources": {"leak_sites": feeds.ransomware_enabled(), "infostealers": feeds.stealer_enabled()},
            "attribution": [s for s, on in ((feeds.RANSOMWARE_SOURCE, feeds.ransomware_enabled()),
                                            (feeds.STEALER_SOURCE, feeds.stealer_enabled())) if on]}


@router.get("/entities/{entity_id}/darkweb")
def entity_darkweb(entity_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    return summary(session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open")).all())


@router.get("/darkweb")
def portfolio_darkweb(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    items = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id)).all()
    names = {i.entity_id: i.entity.name for i in items}
    findings = session.scalars(select(Finding).where(Finding.entity_id.in_(list(names)), Finding.status == "open")).all()
    by_entity: dict[int, list[Finding]] = {}
    for f in _dark(findings):
        by_entity.setdefault(f.entity_id, []).append(f)
    rows = []
    for eid, fs in by_entity.items():
        s = summary(fs)
        rows.append({"entity_id": eid, "name": names[eid], "level": s["level"], "leak_sites": s["leak_sites"],
                     "employees": s["infostealers"]["employees"], "last_employee": s["infostealers"]["last_employee"],
                     "users": s["infostealers"]["users"]})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    rows.sort(key=lambda r: (order[r["level"]], -r["employees"], r["name"]))
    return {"companies": rows, "sources": {"leak_sites": feeds.ransomware_enabled(), "infostealers": feeds.stealer_enabled()},
            "attribution": summary([])["attribution"]}
