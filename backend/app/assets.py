"""System importance (asset value), issue priority, and the hosting map.

Not every system matters equally. A missing header on a parked marketing page is not the same as the same
issue on the login page that customers type passwords into. We classify each system as high, medium or
low value from what it visibly does (login, payments, email, remote access, an interactive app or a static
page) and rank every issue by severity x value. We also record, from public routing data, which network
(hosting provider) and country each system is in, so data held outside India or in high-risk
jurisdictions is visible.
"""

from __future__ import annotations

import ipaddress
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .collectors.dns_util import LookupFailed, resolve, txt_records
from .models import AssetProfile, Entity, Finding, User

router = APIRouter(prefix="/api")
MAX_ASSETS = 300

HIGH_LABELS = {"login", "signin", "sso", "auth", "idp", "id", "accounts", "account", "secure", "pay", "payment",
               "payments", "checkout", "billing", "vpn", "remote", "citrix", "owa", "webmail", "mail", "exchange",
               "autodiscover", "admin", "portal", "netbanking", "banking", "ibank", "hr", "hrms", "erp", "crm",
               "sap", "my", "customer", "customers", "partner", "partners", "vendor", "vendors", "gateway"}
MEDIUM_LABELS = {"api", "app", "apps", "www", "shop", "store", "dashboard", "support", "help", "service", "services",
                 "online", "web", "m", "mobile", "uat", "staging", "dev", "test", "beta"}
HIGH_VALUE_CODES = ("rdp_exposed", "vnc_exposed", "telnet_exposed", "smb_exposed", "db_exposed", "docker_api_exposed",
                    "ics_exposed", "ftp_exposed")
# Comprehensive sanctions or FATF "call for action" lists; data or systems here raise legal and security risk.
HIGH_RISK_COUNTRIES = {"KP": "North Korea", "IR": "Iran", "MM": "Myanmar", "SY": "Syria", "CU": "Cuba",
                       "RU": "Russia", "BY": "Belarus"}
PRIORITY = {  # (severity, value) -> priority 1 (fix first) .. 4
    ("critical", "high"): 1, ("critical", "medium"): 1, ("critical", "low"): 2,
    ("high", "high"): 1, ("high", "medium"): 2, ("high", "low"): 3,
    ("medium", "high"): 2, ("medium", "medium"): 3, ("medium", "low"): 4,
    ("low", "high"): 3, ("low", "medium"): 4, ("low", "low"): 4,
}


def priority(severity: str, value: str | None) -> int:
    return PRIORITY.get((severity, value or "medium"), 4)


def classify_host(host: str, domain: str, page: dict | None, mx_hosts: set[str]) -> tuple[str, list[str]]:
    labels = set(host.removesuffix(domain).strip(".").replace("-", ".").split(".")) - {""}
    reasons = []
    if page and page.get("login"):
        reasons.append("has a login form")
    if page and page.get("payment"):
        reasons.append("takes payments")
    if host in mx_hosts:
        reasons.append("receives the company's email")
    if labels & HIGH_LABELS:
        reasons.append(f"name suggests {sorted(labels & HIGH_LABELS)[0]} system")
    if reasons:
        return "high", reasons
    if page and (page.get("session") or page.get("forms")):
        reasons.append("interactive web application")
    if host in (domain, f"www.{domain}"):
        reasons.append("main website")
    if labels & MEDIUM_LABELS:
        reasons.append(f"name suggests {sorted(labels & MEDIUM_LABELS)[0]} system")
    if reasons:
        return "medium", reasons
    return "low", ["no sign of logins, payments or interactive features"]


def cymru(ip: str) -> dict:
    """ASN, prefix and country for an IP from the Team Cymru IP-to-ASN DNS service (free, DNS only)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {}
    if addr.version != 4:
        return {}
    try:
        txt = txt_records(".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com")
        if not txt:
            return {}
        asn, _prefix, cc = [p.strip() for p in txt[0].split("|")][:3]
        asn = asn.split()[0]
        name = txt_records(f"AS{asn}.asn.cymru.com")
        provider = name[0].split("|")[-1].strip() if name else None
        return {"asn": asn, "country": (cc or "")[:2].upper() or None, "provider": provider}
    except (LookupFailed, ValueError, IndexError):
        return {}


def _first_ip(host: str) -> str | None:
    try:
        recs = resolve(host, "A")
    except LookupFailed:
        return None
    for r in recs:
        ip = str(getattr(r, "address", r))
        if ipaddress.ip_address(ip).is_global:
            return ip
    return None


def build(entity: Entity, pages: dict, lookup=cymru, first_ip=_first_ip) -> list[dict]:
    from .scan import hosts_for

    domain = entity.primary_domain
    try:
        mx_hosts = {str(r.exchange).rstrip(".").lower() for r in resolve(domain, "MX")}
    except LookupFailed:
        mx_hosts = set()
    hosts = hosts_for(entity)
    ips = [a.value for a in entity.assets if a.type == "ip"]
    rows = []
    for h in hosts:
        value, reasons = classify_host(h, domain, pages.get(h), mx_hosts)
        rows.append({"asset": h, "kind": "host", "value": value, "reasons": reasons})
    for ip in ips:
        rows.append({"asset": ip, "kind": "ip", "value": "medium", "reasons": ["server address"], "ip": ip})
    rows = rows[:MAX_ASSETS]

    def enrich(row):
        ip = row.get("ip") or first_ip(row["asset"])
        info = lookup(ip) if ip else {}
        return {**row, "ip": ip, **info}

    with ThreadPoolExecutor(max_workers=16) as pool:
        return list(pool.map(enrich, rows))


def refresh(session: Session, entity: Entity, pages: dict, lookup=cymru, first_ip=_first_ip) -> None:
    rows = build(entity, pages, lookup, first_ip)
    # Exposed admin services make the server they run on high value.
    hot = {f.asset_value for f in session.scalars(select(Finding).where(
        Finding.entity_id == entity.id, Finding.status == "open")) if f.code.startswith(HIGH_VALUE_CODES)}
    existing = {p.asset: p for p in session.scalars(select(AssetProfile).where(AssetProfile.entity_id == entity.id))}
    now = datetime.now(timezone.utc)
    seen = set()
    for r in rows:
        if r["asset"] in seen:
            continue
        seen.add(r["asset"])
        if r["asset"] in hot and r["value"] != "high":
            r["value"], r["reasons"] = "high", ["remote access or database open to the internet"]
        p = existing.get(r["asset"]) or AssetProfile(entity_id=entity.id, asset=r["asset"])
        p.kind, p.value, p.reasons, p.ip = r["kind"], r["value"], r["reasons"][:4], r.get("ip")
        p.asn, p.provider = r.get("asn"), (r.get("provider") or None) and r["provider"][:255]
        p.country, p.updated_at = r.get("country"), now
        session.add(p)
    for asset, p in existing.items():
        if asset not in seen:
            session.delete(p)
    session.commit()


def refresh_after_scan(session: Session, entity: Entity) -> None:
    if os.environ.get("ASSET_PROFILES", "on") == "off":
        return
    try:
        refresh(session, entity, getattr(entity, "_web_profiles", {}) or {})
    except Exception:  # profiling must never lose a completed scan
        session.rollback()


def values(session: Session, entity_id: int) -> dict[str, str]:
    return {p.asset: p.value for p in session.scalars(select(AssetProfile).where(AssetProfile.entity_id == entity_id))}


def prioritise(findings: list[Finding], vals: dict[str, str]) -> list[dict]:
    return [{"id": f.id, "severity": f.severity, "value": vals.get(f.asset_value, "medium"),
             "priority": priority(f.severity, vals.get(f.asset_value)) if f.severity != "info" else 4} for f in findings]


def hosting_summary(profiles: list[AssetProfile], home: str = "IN") -> dict:
    countries: dict[str, int] = {}
    providers: dict[str, int] = {}
    for p in profiles:
        if p.country:
            countries[p.country] = countries.get(p.country, 0) + 1
        if p.provider:
            providers[p.provider] = providers.get(p.provider, 0) + 1
    located = sum(countries.values())
    return {"countries": sorted(({"code": c, "count": n, "high_risk": c in HIGH_RISK_COUNTRIES,
                                  "name": HIGH_RISK_COUNTRIES.get(c)} for c, n in countries.items()), key=lambda x: -x["count"]),
            "providers": sorted(({"name": k, "count": n} for k, n in providers.items()), key=lambda x: -x["count"])[:15],
            "home_country": home, "outside_home": sum(n for c, n in countries.items() if c != home), "located": located,
            "high_risk": sorted({p.asset for p in profiles if p.country in HIGH_RISK_COUNTRIES})}


@router.get("/entities/{entity_id}/assets")
def entity_assets(entity_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item
    from .orgsettings import settings_for

    _portfolio_item(session, user, entity_id)
    profiles = session.scalars(select(AssetProfile).where(AssetProfile.entity_id == entity_id)).all()
    open_findings = session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open")).all()
    vals = {p.asset: p.value for p in profiles}
    pri = prioritise(open_findings, vals)
    matrix = {sev: {v: 0 for v in ("high", "medium", "low")} for sev in ("critical", "high", "medium", "low")}
    for f in pri:
        if f["severity"] in matrix:
            matrix[f["severity"]][f["value"]] += 1
    issues = {}
    for f in open_findings:
        issues[f.asset_value] = issues.get(f.asset_value, 0) + 1
    order = {"high": 0, "medium": 1, "low": 2}
    return {
        "assets": [{"asset": p.asset, "kind": p.kind, "value": p.value, "reasons": p.reasons, "ip": p.ip, "asn": p.asn,
                    "provider": p.provider, "country": p.country, "high_risk_country": p.country in HIGH_RISK_COUNTRIES,
                    "issues": issues.get(p.asset, 0)}
                   for p in sorted(profiles, key=lambda p: (order.get(p.value, 9), -issues.get(p.asset, 0), p.asset))],
        "counts": {v: sum(p.value == v for p in profiles) for v in ("high", "medium", "low")},
        "matrix": matrix, "priorities": {str(n): sum(f["priority"] == n for f in pri) for n in (1, 2, 3, 4)},
        "finding_priority": {str(f["id"]): f["priority"] for f in pri},
        "hosting": hosting_summary(profiles, settings_for(session, user.org_id)["country"]),
    }
