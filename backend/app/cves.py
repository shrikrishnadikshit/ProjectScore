"""CVE enrichment: CVSS base scores from the NIST National Vulnerability Database and EPSS exploit
probabilities from FIRST, cached in the database.

Both sources are free. NVD allows 5 requests per 30 seconds without a key (50 with NVD_API_KEY), so
lookups run in a background thread after each scan and results show up once fetched.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db
from .models import CveInfo

logger = logging.getLogger("projectscore.cves")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
REFRESH = timedelta(days=14)
MAX_PER_RUN = 120
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_running = threading.Lock()


def parse_nvd(data: dict) -> dict | None:
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        rows = metrics.get(key) or []
        if not rows:
            continue
        primary = next((r for r in rows if r.get("type") == "Primary"), rows[0])
        d = primary.get("cvssData", {})
        severity = d.get("baseSeverity") or primary.get("baseSeverity")
        out = {"cvss": d.get("baseScore"), "cvss_version": version, "cvss_severity": (severity or "").lower() or None,
               "cvss_vector": d.get("vectorString")}
        break
    else:
        out = {"cvss": None, "cvss_version": None, "cvss_severity": None, "cvss_vector": None}
    desc = next((x.get("value") for x in cve.get("descriptions", []) if x.get("lang") == "en"), None)
    out["description"] = (desc or "")[:1000] or None
    return out


def parse_epss(data: dict) -> dict[str, tuple[float, float]]:
    out = {}
    for row in data.get("data", []):
        try:
            out[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
        except (KeyError, ValueError):
            continue
    return out


def fetch_nvd(client: httpx.Client, cve: str) -> dict | None:
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    for attempt in range(3):
        resp = client.get(NVD_URL, params={"cveId": cve}, headers=headers)
        if resp.status_code in (403, 429, 503) and attempt < 2:
            time.sleep(10 * (attempt + 1))
            continue
        resp.raise_for_status()
        return parse_nvd(resp.json())
    return None


def fetch_epss(client: httpx.Client, cves: list[str]) -> dict[str, tuple[float, float]]:
    out = {}
    for i in range(0, len(cves), 80):
        resp = client.get(EPSS_URL, params={"cve": ",".join(cves[i:i + 80])})
        resp.raise_for_status()
        out.update(parse_epss(resp.json()))
    return out


def lookup(session: Session, cves: set[str]) -> dict[str, dict]:
    if not cves:
        return {}
    rows = session.scalars(select(CveInfo).where(CveInfo.cve_id.in_(sorted(cves)))).all()
    return {r.cve_id: {"cvss": r.cvss, "cvss_version": r.cvss_version, "severity": r.cvss_severity,
                       "vector": r.cvss_vector, "epss": r.epss, "epss_percentile": r.epss_percentile,
                       "description": r.description} for r in rows}


def stale(session: Session, cves: set[str]) -> list[str]:
    now = datetime.now(timezone.utc)
    have = {r.cve_id: r.fetched_at for r in session.scalars(select(CveInfo).where(CveInfo.cve_id.in_(sorted(cves))))}
    def old(ts):
        return ts is None or now - (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)) > REFRESH
    return sorted(c for c in cves if old(have.get(c)))


def enrich(cves: set[str], nvd=fetch_nvd, epss=fetch_epss, pause: float | None = None) -> int:
    """Fetch and store data for CVEs that are missing or stale. Returns how many were updated."""
    cves = {c.upper() for c in cves if CVE_RE.match(c.upper())}
    if not cves or not _running.acquire(blocking=False):
        return 0
    try:
        session = db.SessionLocal()
        try:
            todo = stale(session, cves)[:MAX_PER_RUN]
            if not todo:
                return 0
            pause = pause if pause is not None else (0.7 if os.environ.get("NVD_API_KEY") else 6.5)
            with httpx.Client(timeout=20.0, headers={"User-Agent": "ProjectScore-Scanner"}) as client:
                try:
                    scores = epss(client, todo)
                except httpx.HTTPError as exc:
                    logger.warning("EPSS lookup failed: %s", exc)
                    scores = {}
                done = 0
                for i, cve in enumerate(todo):
                    try:
                        info = nvd(client, cve) or {}
                    except httpx.HTTPError as exc:
                        logger.warning("NVD lookup failed for %s: %s", cve, exc)
                        info = {}
                    row = session.get(CveInfo, cve) or CveInfo(cve_id=cve)
                    for k, v in info.items():
                        setattr(row, k, v)
                    if cve in scores:
                        row.epss, row.epss_percentile = scores[cve]
                    row.fetched_at = datetime.now(timezone.utc)
                    session.add(row)
                    session.commit()
                    done += 1
                    if pause and i < len(todo) - 1:
                        time.sleep(pause)
                return done
        finally:
            session.close()
    finally:
        _running.release()


def enrich_async(cves: set[str]) -> None:
    if cves and os.environ.get("CVE_ENRICHMENT", "on").lower() != "off":
        threading.Thread(target=enrich, args=(set(cves),), daemon=True).start()


def cves_in(findings) -> set[str]:
    out = set()
    for f in findings:
        for c in (f.evidence or {}).get("cves", []) or []:
            if isinstance(c, str) and CVE_RE.match(c.upper()):
                out.add(c.upper())
    return out


def severity_for(max_cvss: float | None, default: str) -> str:
    if max_cvss is None:
        return default
    return "high" if max_cvss >= 9 else "medium" if max_cvss >= 7 else "low"
