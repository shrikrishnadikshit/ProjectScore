"""Which of my vendors run product X? (BRS VULN-004)

When a new vulnerability is announced (say, in MOVEit Transfer or Citrix NetScaler), you want the list of
vendors that could be affected, today. We search what our scans already know about each vendor:

- software and versions their web servers disclose, and JavaScript libraries on their pages (scan findings),
- products named in the CVEs found on their systems (CVE.org records and the CISA KEV catalogue),
- the SaaS and infrastructure services they visibly rely on (email, DNS, identity, hosting, from public DNS),
- the network or cloud provider that hosts each of their systems.

Nothing new is sent to the vendors; this only reads stored results. Matches from outside-in data are signs,
not proof, so each one says where it came from.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import AssetProfile, Finding, PortfolioItem, User, VendorDetection

router = APIRouter(prefix="/api")
MAX_PER_VENDOR = 8


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9.]+", " ", (s or "").lower()).strip()


def _hit(q: str, *texts) -> bool:
    return any(q in _norm(t) for t in texts if t)


def _kev_products() -> dict[str, str]:
    try:
        from .collectors.kev import kev_entries

        return {e["cveID"]: f"{e.get('vendorProject', '')} {e.get('product', '')}".strip() for e in kev_entries()}
    except Exception:
        return {}


def search(session: Session, org_id: int, query: str, kev: dict[str, str] | None = None) -> list[dict]:
    from .advisories import lookup as advisory_lookup
    from .cves import cves_in

    q = _norm(query)
    if len(q) < 2:
        raise HTTPException(422, "type at least 2 letters")
    items = {i.entity_id: i for i in session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == org_id))}
    if not items:
        return []
    ids = list(items)
    hits: dict[int, list[dict]] = {}

    def add(eid: int, source: str, what: str, where: str | None = None) -> None:
        rows = hits.setdefault(eid, [])
        if len(rows) < MAX_PER_VENDOR and not any(r["what"] == what and r["where"] == where for r in rows):
            rows.append({"source": source, "what": what, "where": where})

    findings = session.scalars(select(Finding).where(Finding.entity_id.in_(ids), Finding.status == "open")).all()
    by_entity: dict[int, list[Finding]] = {}
    for f in findings:
        by_entity.setdefault(f.entity_id, []).append(f)
        ev = f.evidence or {}
        sw = ev.get("software") or (f"{ev['library']} {ev.get('version', '')}".strip() if ev.get("library") else None)
        if sw and _hit(q, sw):
            add(f.entity_id, "Software seen on their server", sw.replace("/", " "), f.asset_value)
        elif _hit(q, f.title):
            add(f.entity_id, "Scan finding", f.title, f.asset_value)

    kev = _kev_products() if kev is None else kev
    for eid, fs in by_entity.items():
        cves = cves_in(fs)
        if not cves:
            continue
        intel = advisory_lookup(session, cves)
        for c in sorted(cves):
            names = list((intel.get(c) or {}).get("products") or [])
            if kev.get(c):
                names.append(kev[c])
            for n in names:
                if _hit(q, n):
                    words = n.split()
                    n = " ".join(w for i, w in enumerate(words) if i == 0 or w.lower() != words[i - 1].lower())
                    add(eid, "Product named in a CVE on their systems", f"{n} ({c})")
                    break

    for d in session.scalars(select(VendorDetection).where(VendorDetection.entity_id.in_(ids))):
        for v in d.vendors or []:
            if _hit(q, v.get("name"), v.get("domain")):
                add(d.entity_id, "Service they use", f"{v.get('name')} ({v.get('category', 'service')})")

    for a in session.scalars(select(AssetProfile).where(AssetProfile.entity_id.in_(ids))):
        if _hit(q, a.provider):
            add(a.entity_id, "Hosting provider", a.provider, a.asset)

    out = [{"entity_id": eid, "name": items[eid].entity.name, "domain": items[eid].entity.primary_domain,
            "tier": items[eid].tier, "matches": rows} for eid, rows in hits.items()]
    return sorted(out, key=lambda r: (r["tier"] or 9, r["name"].lower()))


@router.get("/product-search")
def product_search(q: str, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    rows = search(session, user.org_id, q[:100])
    return {"query": q[:100], "vendors": rows, "total": len(rows)}


@router.get("/product-search/suggestions")
def suggestions(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> list[dict]:
    """The products and services seen most often across your vendors, to search with one click."""
    ids = [i.entity_id for i in session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id))]
    if not ids:
        return []
    seen: dict[str, set[int]] = {}
    for d in session.scalars(select(VendorDetection).where(VendorDetection.entity_id.in_(ids))):
        for v in d.vendors or []:
            if v.get("name"):
                seen.setdefault(v["name"], set()).add(d.entity_id)
    for f in session.scalars(select(Finding).where(Finding.entity_id.in_(ids), Finding.status == "open")):
        ev = f.evidence or {}
        name = (ev.get("software") or "").split("/")[0] or ev.get("library")
        if name:
            seen.setdefault(name, set()).add(f.entity_id)
    ranked = sorted(seen.items(), key=lambda kv: (-len(kv[1]), kv[0].lower()))[:20]
    return [{"name": k, "vendors": len(v)} for k, v in ranked]
