"""Breach history (BRS factor "breach_history") from the public Have I Been Pwned breach catalogue.

The catalogue of breached websites is free and published under CC BY 4.0 (attribution: haveibeenpwned.com).
It lists the domain of each breached service, when the breach happened and what data was exposed. We match
breaches to the company's domain. Findings decay with a one-year half-life from the breach date.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import date, datetime, timezone

import httpx

from . import RawFinding

logger = logging.getLogger("projectscore.breaches")

URL = "https://haveibeenpwned.com/api/v3/breaches"
_TTL = 24 * 3600
MAX_AGE_YEARS = 6
_lock = threading.Lock()
_cache: dict = {"rows": None, "loaded": 0.0}


def catalogue() -> list[dict] | None:
    if os.environ.get("BREACH_FEED", "on").lower() == "off":
        return None
    with _lock:
        if time.time() - _cache["loaded"] < _TTL and _cache["rows"] is not None:
            return _cache["rows"]
        try:
            resp = httpx.get(URL, timeout=30.0, headers={"User-Agent": "ProjectScore-Scanner"})
            resp.raise_for_status()
            _cache["rows"] = resp.json()
            _cache["loaded"] = time.time()
            logger.info("loaded %d breaches", len(_cache["rows"]))
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("could not load the breach catalogue: %s", exc)
            _cache["loaded"] = time.time() - _TTL + 900
        return _cache["rows"]


def evaluate(domain: str, rows: list[dict], today: date | None = None) -> list[RawFinding]:
    today = today or datetime.now(timezone.utc).date()
    findings = []
    for b in rows:
        bd = (b.get("Domain") or "").lower()
        if not bd or not (bd == domain or bd.endswith("." + domain)):
            continue
        if b.get("IsFabricated") or b.get("IsSpamList") or b.get("IsRetired"):
            continue
        try:
            when = date.fromisoformat(b.get("BreachDate", ""))
        except ValueError:
            continue
        age_years = (today - when).days / 365.25
        if age_years > MAX_AGE_YEARS:
            continue
        classes = b.get("DataClasses") or []
        has_passwords = any("password" in c.lower() for c in classes)
        severity = "high" if has_passwords and age_years <= 2 else "medium" if age_years <= 3 else "low"
        count = b.get("PwnCount") or 0
        findings.append(RawFinding(
            "breach_history", f"breach_{(b.get('Name') or bd).lower()}",
            f"Data breach in {when:%B %Y}: {count:,} accounts exposed ({', '.join(classes[:4]) or 'details unknown'})",
            severity, bd,
            {"event_date": when.isoformat(), "source": "Have I Been Pwned (CC BY 4.0)", "title": b.get("Title"),
             "accounts": count, "data_classes": classes, "verified": bool(b.get("IsVerified"))},
            1.0 if b.get("IsVerified") else 0.6))
    return findings


def collect(domain: str, rows: list[dict] | None = None) -> tuple[list[RawFinding], int]:
    rows = catalogue() if rows is None else rows
    if rows is None:
        return [], 0
    return evaluate(domain, rows), 1
