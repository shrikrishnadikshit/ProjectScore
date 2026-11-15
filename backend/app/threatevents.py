"""Threat events: when a newly announced, actively exploited vulnerability hits companies in your portfolio.

New entries in the CISA Known Exploited Vulnerabilities catalogue are matched against what our scans saw
at each vendor: the exact CVE on an exposed system, or the same software product. This answers the
question a customer asks on the day of a big incident: "which of my vendors are affected?"
"""

from __future__ import annotations

from datetime import date, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .collectors import kev
from .models import Finding, PortfolioItem, User

router = APIRouter(prefix="/api")

# Software we can identify from outside -> (KEV vendorProject, words that must appear in the KEV product)
PRODUCTS = {
    "apache": ("apache", "http server"),
    "nginx": ("f5", "nginx"),
    "microsoft-iis": ("microsoft", "internet information services"),
    "php": ("php", "php"),
    "openssl": ("openssl", "openssl"),
    "lighttpd": ("lighttpd", "lighttpd"),
}


def _software(f: Finding) -> str | None:
    sw = (f.evidence or {}).get("software")
    return sw.split("/")[0].lower() if isinstance(sw, str) else None


def match(events: list[dict], findings: list[Finding], names: dict[int, str]) -> list[dict]:
    by_cve: dict[str, set[int]] = {}
    by_product: dict[str, set[int]] = {}
    for f in findings:
        for c in (f.evidence or {}).get("cves", []) or []:
            by_cve.setdefault(str(c).upper(), set()).add(f.entity_id)
        sw = _software(f)
        if sw in PRODUCTS:
            by_product.setdefault(sw, set()).add(f.entity_id)
    out = []
    for e in events:
        cve = (e.get("cveID") or "").upper()
        exact = by_cve.get(cve, set())
        maybe = set()
        vp, prod = (e.get("vendorProject") or "").lower(), (e.get("product") or "").lower()
        for sw, (want_vendor, want_product) in PRODUCTS.items():
            if want_vendor in vp and want_product in prod:
                maybe |= by_product.get(sw, set())
        maybe -= exact
        affected = ([{"id": i, "name": names[i], "match": "confirmed"} for i in sorted(exact, key=names.get)]
                    + [{"id": i, "name": names[i], "match": "same software"} for i in sorted(maybe, key=names.get)])
        out.append({**e, "ransomware": (e.get("knownRansomwareCampaignUse") or "").lower() == "known",
                    "affected": affected})
    return out


def recent(entries: list[dict], days: int, today: date | None = None) -> list[dict]:
    today = today or date.today()
    cutoff = (today - timedelta(days=days)).isoformat()
    return sorted([e for e in entries if (e.get("dateAdded") or "") >= cutoff],
                  key=lambda e: (e.get("dateAdded") or "", e.get("cveID") or ""), reverse=True)


@router.get("/threat-events")
def threat_events(days: int = 30, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    days = max(1, min(days, 365))
    items = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id)).all()
    names = {i.entity_id: i.entity.name for i in items}
    findings = session.scalars(select(Finding).where(Finding.entity_id.in_(list(names)), Finding.status == "open")).all()
    entries = kev.kev_entries()
    events = match(recent(entries, days), findings, names)
    return {"days": days, "catalogue_loaded": bool(entries), "events": events,
            "affected_companies": len({a["id"] for e in events for a in e["affected"]})}
