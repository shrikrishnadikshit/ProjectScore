"""Open vulnerability and advisory sources, joined to the CVEs our scans find.

On top of NIST NVD (CVSS) and FIRST EPSS in cves.py, the CISA KEV catalogue in threatevents.py and CERT-In in
certin.py, this adds, for each CVE seen at a company:

- the official CVE record from the CVE Program (cveawg.mitre.org): who assigned it, the affected products and
  CISA's own assessment (SSVC: is it exploited, can it be automated, how bad is the impact);
- GitHub Security Advisories (CC BY 4.0): the affected open-source packages and the version that fixes them;
- CIRCL Vulnerability-Lookup sightings: how often the CVE has been seen discussed, exploited or given a public
  proof-of-concept exploit.

It also reads CISA's cybersecurity and ICS advisory RSS feeds every 6 hours and links each advisory to the
CVEs it mentions. OpenCVE is not used: it repackages NVD, MITRE and CISA data, which we read at the source.

Switch off with ADVISORY_FEEDS=off. A GITHUB_TOKEN (no scopes needed) raises GitHub's limit from 60 to
5,000 requests an hour.
"""

from __future__ import annotations

import html as htmllib
import logging
import os
import re
import threading
import time
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import CisaAdvisory, CveIntel, Finding, PortfolioItem, User

logger = logging.getLogger("projectscore.advisories")
router = APIRouter(prefix="/api")

CVE_RECORD_URL = "https://cveawg.mitre.org/api/cve/{}"
GITHUB_URL = "https://api.github.com/advisories"
CIRCL_SIGHTINGS_URL = "https://vulnerability.circl.lu/api/sighting/"
CISA_FEEDS = {"general": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
              "ics": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"}
HEADERS = {"User-Agent": "ProjectScore-Scanner (+https://projectscore.onrender.com/scanner)"}
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CODE_RE = re.compile(r"\b(ICSA-\d{2}-\d{3}-\d{2}[A-Z]?|ICSMA-\d{2}-\d{3}-\d{2}|AA\d{2}-\d{3}[A-Z]?)\b")
REFRESH = timedelta(days=7)
MAX_PER_RUN = 40
CISA_EVERY = timedelta(hours=6)
SOURCES = [
    {"name": "NIST National Vulnerability Database", "url": "https://nvd.nist.gov/", "use": "CVSS severity scores"},
    {"name": "CVE Program", "url": "https://www.cve.org/", "use": "Official CVE records, affected products, CISA exploitation assessment (SSVC)"},
    {"name": "GitHub Advisory Database", "url": "https://github.com/advisories", "use": "Affected open-source packages and fixed versions (CC BY 4.0)"},
    {"name": "CISA Known Exploited Vulnerabilities", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "use": "Vulnerabilities exploited in the wild"},
    {"name": "CISA Cybersecurity Advisories", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories", "use": "Advisories and ICS advisories linked to CVEs"},
    {"name": "CIRCL Vulnerability-Lookup", "url": "https://vulnerability.circl.lu/", "use": "Sightings: seen, exploited, proof-of-concept published"},
    {"name": "FIRST EPSS", "url": "https://www.first.org/epss/", "use": "Chance of exploitation in the next 30 days"},
    {"name": "CERT-In", "url": "https://www.cert-in.org.in/", "use": "Indian advisories and vulnerability notes (facts and links only)"},
]
_lock = threading.Lock()
_cisa = {"running": False, "last": None, "error": None}


def enabled() -> bool:
    return os.environ.get("ADVISORY_FEEDS", "on").lower() != "off"


def _aware(ts: datetime) -> datetime:
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


# ---------- parsers (pure, tested) ----------

def parse_cve_record(data: dict) -> dict:
    """CVE JSON 5 record -> assigner, title, short description, affected products, CISA SSVC and KEV flags."""
    meta = data.get("cveMetadata") or {}
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}
    desc = next((d.get("value") for d in cna.get("descriptions") or [] if str(d.get("lang", "")).startswith("en")), None)
    products = []
    for a in cna.get("affected") or []:
        name = " ".join(x for x in (a.get("vendor"), a.get("product")) if x and x.lower() not in ("n/a", "unknown"))
        if name and name not in products:
            products.append(name[:120])
    out = {"state": meta.get("state"), "assigner": meta.get("assignerShortName"),
           "published": (meta.get("datePublished") or "")[:10] or None,
           "title": (cna.get("title") or "")[:300] or None, "description": (desc or "")[:600] or None,
           "products": products[:10]}
    for adp in containers.get("adp") or []:
        for m in adp.get("metrics") or []:
            other = m.get("other") or {}
            if other.get("type") == "ssvc":
                opts = {}
                for o in (other.get("content") or {}).get("options") or []:
                    opts.update({k.lower().replace(" ", "_"): str(v).lower() for k, v in o.items()})
                out["ssvc"] = {k: opts.get(k) for k in ("exploitation", "automatable", "technical_impact")}
            elif other.get("type") == "kev":
                out["kev"] = True
    return out


def parse_github(items: list) -> list[dict]:
    out = []
    for a in items or []:
        if not isinstance(a, dict) or not a.get("ghsa_id"):
            continue
        pkgs = []
        for v in a.get("vulnerabilities") or []:
            p = v.get("package") or {}
            if p.get("name"):
                pkgs.append({"ecosystem": p.get("ecosystem"), "name": p["name"][:120],
                             "vulnerable": (v.get("vulnerable_version_range") or "")[:80] or None,
                             "patched": (v.get("first_patched_version") or None) if isinstance(v.get("first_patched_version"), str)
                             else ((v.get("first_patched_version") or {}).get("identifier") if isinstance(v.get("first_patched_version"), dict) else None)})
        out.append({"id": a["ghsa_id"], "url": a.get("html_url") or f"https://github.com/advisories/{a['ghsa_id']}",
                    "severity": a.get("severity"), "summary": (a.get("summary") or "")[:300],
                    "reviewed": a.get("type") == "reviewed", "packages": pkgs[:10]})
    return out[:5]


def parse_sightings(data) -> dict:
    """CIRCL sightings list -> counts by type (seen, exploited, published-proof-of-concept, confirmed, ...)."""
    rows = data.get("data") if isinstance(data, dict) else data
    counts: dict[str, int] = {}
    latest = None
    for s in rows or []:
        if not isinstance(s, dict):
            continue
        t = str(s.get("type") or "seen").lower()
        counts[t] = counts.get(t, 0) + 1
        ts = s.get("creation_timestamp") or s.get("created_at")
        if isinstance(ts, str) and (latest is None or ts > latest):
            latest = ts
    total = (data.get("metadata") or {}).get("count") if isinstance(data, dict) else None
    return {"counts": counts, "total": total if isinstance(total, int) else sum(counts.values()),
            "latest": latest[:10] if latest else None}


def parse_feed(xml: str, kind: str) -> list[dict]:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return []
    out = []
    for item in root.iter("item"):
        title = htmllib.unescape((item.findtext("title") or "").strip())
        link = (item.findtext("link") or "").strip()
        if not title or not link.startswith("https://www.cisa.gov/"):
            continue
        body = item.findtext("description") or ""
        try:
            published = parsedate_to_datetime(item.findtext("pubDate") or "").date()
        except (TypeError, ValueError):
            published = None
        code = CODE_RE.search(title + " " + link.upper())
        cves = sorted({c.upper() for c in CVE_RE.findall(title + " " + body)})
        out.append({"url": link[:500], "title": title[:400], "kind": kind, "published": published,
                    "code": code.group(1) if code else None, "cves": cves[:200]})
    return out


# ---------- per-CVE enrichment ----------

def fetch_record(client: httpx.Client, cve: str) -> dict | None:
    r = client.get(CVE_RECORD_URL.format(cve))
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return parse_cve_record(r.json())


def fetch_github(client: httpx.Client, cve: str) -> list[dict]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    r = client.get(GITHUB_URL, params={"cve_id": cve, "per_page": 5}, headers=headers)
    r.raise_for_status()
    return parse_github(r.json())


def fetch_sightings(client: httpx.Client, cve: str) -> dict:
    r = client.get(CIRCL_SIGHTINGS_URL, params={"vuln_id": cve, "per_page": 100})
    r.raise_for_status()
    return parse_sightings(r.json())


def stale(session: Session, cves: set[str]) -> list[str]:
    now = datetime.now(timezone.utc)
    have = {r.cve_id: r.fetched_at for r in session.scalars(select(CveIntel).where(CveIntel.cve_id.in_(sorted(cves))))}
    return sorted(c for c in cves if have.get(c) is None or now - _aware(have[c]) > REFRESH)


_running = threading.Lock()


def enrich(cves: set[str], record=fetch_record, github=fetch_github, sightings=fetch_sightings,
           pause: float | None = None) -> int:
    cves = {c.upper() for c in cves if CVE_RE.fullmatch(c.upper())}
    if not cves or not _running.acquire(blocking=False):
        return 0
    try:
        session = db.SessionLocal()
        try:
            todo = stale(session, cves)[:MAX_PER_RUN]
            pause = 1.0 if pause is None else pause
            with httpx.Client(timeout=20.0, headers=HEADERS, follow_redirects=True) as client:
                github_ok = True
                for i, cve in enumerate(todo):
                    row = session.get(CveIntel, cve) or CveIntel(cve_id=cve, record={}, github=[], sightings={})
                    for name, fn, attr in (("CVE.org", record, "record"), ("GitHub", github, "github"),
                                           ("CIRCL", sightings, "sightings")):
                        if attr == "github" and not github_ok:
                            continue
                        try:
                            val = fn(client, cve)
                            setattr(row, attr, val if val is not None else ({} if attr != "github" else []))
                        except httpx.HTTPStatusError as exc:
                            if attr == "github" and exc.response.status_code in (403, 429):
                                github_ok = False  # rate limited: try again next run
                            logger.warning("%s lookup failed for %s: HTTP %s", name, cve, exc.response.status_code)
                        except (httpx.HTTPError, ValueError) as exc:
                            logger.warning("%s lookup failed for %s: %s", name, cve, type(exc).__name__)
                    row.fetched_at = datetime.now(timezone.utc)
                    session.add(row)
                    session.commit()
                    if pause and i < len(todo) - 1:
                        time.sleep(pause)
            return len(todo)
        finally:
            session.close()
    finally:
        _running.release()


def enrich_async(cves: set[str]) -> None:
    if cves and enabled():
        threading.Thread(target=enrich, args=(set(cves),), daemon=True, name="advisories").start()


def cisa_by_cve(session: Session, cves: list[str]) -> dict[str, list[dict]]:
    if not cves:
        return {}
    want, out = set(cves), {}
    for a in session.scalars(select(CisaAdvisory).order_by(CisaAdvisory.published.desc())).all():
        for c in set(a.cves or []) & want:
            out.setdefault(c, []).append({"code": a.code, "title": a.title, "url": a.url, "kind": a.kind})
    return {c: v[:3] for c, v in out.items()}


def lookup(session: Session, cves: set[str]) -> dict[str, dict]:
    """Per-CVE intelligence for a company page."""
    if not cves:
        return {}
    rows = {r.cve_id: r for r in session.scalars(select(CveIntel).where(CveIntel.cve_id.in_(sorted(cves))))}
    cisa = cisa_by_cve(session, sorted(cves))
    out = {}
    for c in cves:
        r = rows.get(c)
        if r is None and c not in cisa:
            continue
        rec = (r.record if r else None) or {}
        out[c] = {"assigner": rec.get("assigner"), "title": rec.get("title"), "products": rec.get("products") or [],
                  "ssvc": rec.get("ssvc"), "github": (r.github if r else None) or [],
                  "sightings": (r.sightings if r else None) or {}, "cisa": cisa.get(c, [])}
    return out


# ---------- CISA advisories ----------

def refresh_cisa(session: Session, fetch=None) -> int:
    added = 0
    known = {u for (u,) in session.execute(select(CisaAdvisory.url))}
    with httpx.Client(timeout=30.0, headers=HEADERS, follow_redirects=True) as client:
        for kind, url in CISA_FEEDS.items():
            if fetch:
                xml = fetch(url)
            else:
                r = client.get(url)
                r.raise_for_status()
                xml = r.text
            for e in parse_feed(xml or "", kind):
                if e["url"] in known:
                    continue
                session.add(CisaAdvisory(**e))
                known.add(e["url"])
                added += 1
    session.commit()
    return added


def refresh_async() -> None:
    if not enabled():
        return
    with _lock:
        if _cisa["running"] or (_cisa["last"] and datetime.now(timezone.utc) - _cisa["last"] < CISA_EVERY):
            return
        _cisa["running"] = True

    def run():
        session = db.SessionLocal()
        try:
            n = refresh_cisa(session)
            _cisa["error"] = None
            logger.info("CISA advisories added: %d", n)
        except Exception as exc:  # an outside site must never break the app
            logger.exception("CISA advisory refresh failed")
            _cisa["error"] = type(exc).__name__
            session.rollback()
        finally:
            session.close()
            _cisa["last"] = datetime.now(timezone.utc)
            _cisa["running"] = False

    threading.Thread(target=run, daemon=True, name="cisa-advisories").start()


@router.get("/advisories/sources")
def sources() -> dict:
    return {"sources": SOURCES}


@router.get("/advisories")
def advisories(days: int = 30, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    """Recent CISA advisories, each with the portfolio companies where we saw one of its CVEs."""
    days = max(1, min(days, 365))
    since = date.today() - timedelta(days=days)
    rows = session.scalars(select(CisaAdvisory).where(CisaAdvisory.published >= since)
                           .order_by(CisaAdvisory.published.desc()).limit(200)).all()
    items = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id)).all()
    names = {i.entity_id: i.entity.name for i in items}
    seen: dict[str, set[int]] = {}
    if names:
        for f in session.scalars(select(Finding).where(Finding.entity_id.in_(list(names)), Finding.status == "open")).all():
            for c in (f.evidence or {}).get("cves") or []:
                if isinstance(c, str):
                    seen.setdefault(c.upper(), set()).add(f.entity_id)
    out = []
    for a in rows:
        hit = sorted({e for c in a.cves or [] for e in seen.get(c, ())})
        out.append({"code": a.code, "title": a.title, "url": a.url, "kind": a.kind,
                    "published": a.published.isoformat() if a.published else None, "cves": (a.cves or [])[:20],
                    "cve_count": len(a.cves or []),
                    "affected": [{"entity_id": e, "name": names[e]} for e in hit]})
    if enabled() and _cisa["last"] is None:
        refresh_async()
    return {"items": out, "affected": sum(1 for o in out if o["affected"]), "error": _cisa["error"]}


@router.get("/cves/{cve_id}")
def cve_detail(cve_id: str, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    """Everything we know about one CVE, from every source."""
    from . import certin, cves

    cve = cve_id.upper()
    if not CVE_RE.fullmatch(cve):
        raise HTTPException(422, "not a CVE id")
    return {"cve": cve, "scores": cves.lookup(session, {cve}).get(cve), "intel": lookup(session, {cve}).get(cve),
            "certin": certin.by_cve(session, [cve]).get(cve, []),
            "links": {"nvd": f"https://nvd.nist.gov/vuln/detail/{cve}", "cve_org": f"https://www.cve.org/CVERecord?id={cve}",
                      "github": f"https://github.com/advisories?query={cve}",
                      "circl": f"https://vulnerability.circl.lu/vuln/{cve.lower()}"}}
