"""Dark web monitoring from public aggregators. We never visit dark web sites ourselves.

1. Ransomware leak sites: criminal groups publish the names of companies they claim to have breached on
   their Tor "leak sites". Ransomware.live (https://ransomware.live) tracks these sites and offers a search.
   Its terms allow non-commercial use with attribution; commercial use needs the owner's written approval,
   so this check is OFF unless RANSOMWARE_LIVE=on is set (after that approval).
2. Infostealer logs: malware such as RedLine and Lumma steals saved logins from infected computers, and the
   logs are sold on dark web markets. Hudson Rock's free Cavalier lookup returns how many computers of a
   company's employees and customers were infected, without any personal data. INFOSTEALER_FEED=off disables.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx

from . import RawFinding

logger = logging.getLogger("projectscore.darkweb")

RANSOMWARE_URL = "https://api.ransomware.live/v2/searchvictims/{keyword}"
STEALER_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
RANSOMWARE_SOURCE = "Ransomware.live (ransomware.live)"
STEALER_SOURCE = "Hudson Rock Cavalier (hudsonrock.com)"
_TTL = 24 * 3600
_MIN_GAP = 61.0  # ransomware.live allows one request a minute per endpoint
LEAK_MAX_DAYS = 365
STEALER_RECENT_DAYS = 180
_lock = threading.Lock()
_last_call = {"ransomware": 0.0}
_cache: dict[tuple[str, str], tuple[float, object]] = {}
HEADERS = {"User-Agent": "ProjectScore-Scanner", "Accept": "application/json"}


def ransomware_enabled() -> bool:
    return os.environ.get("RANSOMWARE_LIVE", "off").lower() == "on"


def stealer_enabled() -> bool:
    return os.environ.get("INFOSTEALER_FEED", "on").lower() != "off"


def _cached(kind: str, key: str, fetch):
    now = time.time()
    hit = _cache.get((kind, key))
    if hit and now - hit[0] < _TTL:
        return hit[1]
    value = fetch()
    if value is not None:
        _cache[(kind, key)] = (now, value)
    return value


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _parse_dt(v) -> datetime | None:
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00").replace(" ", "T"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------- Ransomware leak sites ----------

def fetch_leaks(domain: str) -> list[dict] | None:
    keyword = domain.split(".")[0]
    if len(keyword) < 3:
        return []

    def go():
        with _lock:
            wait = _MIN_GAP - (time.time() - _last_call["ransomware"])
            if wait > 0:
                time.sleep(wait)
            _last_call["ransomware"] = time.time()
            try:
                resp = httpx.get(RANSOMWARE_URL.format(keyword=keyword), timeout=30.0, headers=HEADERS)
                if resp.status_code == 404:
                    return []
                resp.raise_for_status()
                data = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning("ransomware.live lookup failed for %s: %s", domain, exc)
                return None
        return data if isinstance(data, list) else data.get("victims", []) if isinstance(data, dict) else []

    return _cached("ransomware", keyword, go)


def match_leaks(records: list[dict], domain: str, name: str) -> list[dict]:
    """Only records naming the company's own domain, or exactly its name; mentions in descriptions don't count."""
    out, want = [], _norm(name)
    for r in records:
        d = (r.get("domain") or r.get("website") or "").lower().strip()
        d = re.sub(r"^https?://", "", d).split("/")[0].removeprefix("www.")
        by_domain = d and (d == domain or d.endswith("." + domain))
        by_name = want and len(want) >= 4 and _norm(r.get("victim") or r.get("post_title") or "") == want
        if by_domain or by_name:
            out.append(r)
    return out


def evaluate_leaks(records: list[dict], domain: str, name: str, now: datetime | None = None) -> list[RawFinding]:
    now = now or datetime.now(timezone.utc)
    findings = []
    for r in match_leaks(records, domain, name):
        when = _parse_dt(r.get("discovered")) or _parse_dt(r.get("attackdate"))
        if when is None or (now - when).days > LEAK_MAX_DAYS:
            continue
        group = r.get("group") or r.get("group_name") or "unknown group"
        by_domain = bool(r.get("domain")) and domain in (r.get("domain") or "").lower()
        findings.append(RawFinding(
            "compromise", f"ransomware_leak_{_norm(group)}_{when:%Y%m%d}",
            f"Named on the {group} ransomware leak site on {when:%d %b %Y}",
            "critical" if (now - when).days <= 90 else "high", domain,
            {"event_date": when.date().isoformat(), "group": group, "victim": r.get("victim"),
             "country": r.get("country"), "sector": r.get("activity"), "link": r.get("url"),
             "matched_on": "domain" if by_domain else "name", "source": RANSOMWARE_SOURCE, "darkweb": True},
            0.8 if by_domain else 0.5))
    return findings


# ---------- Infostealer logs ----------

def fetch_stealers(domain: str) -> dict | None:
    def go():
        try:
            resp = httpx.get(STEALER_URL, params={"domain": domain}, timeout=30.0, headers=HEADERS)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("infostealer lookup failed for %s: %s", domain, exc)
            return None
        return data if isinstance(data, dict) else None

    return _cached("stealer", domain, go)


_HOST = re.compile(r"^(?:https?://)?([a-z0-9•*](?:[a-z0-9•*-]{0,62}[a-z0-9•*])?(?:\.[a-z0-9•*](?:[a-z0-9•*-]{0,62}[a-z0-9•*])?)+)(?:[/:?#]|$)", re.I)


def stealer_summary(data: dict) -> dict:
    fams = {k: v for k, v in (data.get("stealerFamilies") or {}).items() if k != "total" and isinstance(v, int)}
    # Keep only the host name of each login page. The raw entries can contain user names or passwords,
    # which we must never store or show.
    counts: dict[str, int] = {}
    for u in ((data.get("data") or {}).get("employees_urls") or []):
        m = _HOST.match(str(u.get("url") or "")) if isinstance(u, dict) else None
        if m and "@" not in m.group(1):
            counts[m.group(1).lower()] = counts.get(m.group(1).lower(), 0) + int(u.get("occurrence") or 1)
    hosts = [{"url": h, "count": c} for h, c in sorted(counts.items(), key=lambda x: -x[1])[:10]]
    return {"employees": int(data.get("employees") or 0), "users": int(data.get("users") or 0),
            "third_parties": int(data.get("third_parties") or 0),
            "last_employee": data.get("last_employee_compromised"), "last_user": data.get("last_user_compromised"),
            "families": sorted(fams, key=fams.get, reverse=True)[:5], "employee_logins": hosts}


def evaluate_stealers(data: dict, domain: str, now: datetime | None = None) -> list[RawFinding]:
    now = now or datetime.now(timezone.utc)
    s = stealer_summary(data)
    findings = []
    last_emp = _parse_dt(s["last_employee"])
    if s["employees"] > 0:
        recent = last_emp is not None and (now - last_emp).days <= STEALER_RECENT_DAYS
        findings.append(RawFinding(
            "breach_history", "infostealer_employees",
            f"Logins of {s['employees']:,} employee computer{'s' if s['employees'] != 1 else ''} stolen by "
            f"infostealer malware and traded on the dark web", "high" if recent and s["employees"] >= 5 else
            "medium" if recent else "low", domain,
            {**s, "event_date": (last_emp or now).date().isoformat(), "source": STEALER_SOURCE, "darkweb": True}, 0.7))
    last_user = _parse_dt(s["last_user"])
    if s["users"] > 0:
        findings.append(RawFinding(
            "breach_history", "infostealer_customers",
            f"Logins of {s['users']:,} customers or users of this company's sites found in infostealer logs",
            "low", domain,
            {"users": s["users"], "last_user": s["last_user"], "event_date": (last_user or now).date().isoformat(),
             "source": STEALER_SOURCE, "darkweb": True}, 0.5))
    return findings


# ---------- Collector ----------

def collect(domain: str, name: str, leak_fn=None, stealer_fn=None) -> tuple[list[RawFinding], int]:
    findings, checked = [], 0
    if ransomware_enabled() or leak_fn:
        rows = (leak_fn or fetch_leaks)(domain)
        if rows is not None:
            checked += 1
            findings += evaluate_leaks(rows, domain, name)
    if stealer_enabled() or stealer_fn:
        data = (stealer_fn or fetch_stealers)(domain)
        if data is not None:
            checked += 1
            findings += evaluate_stealers(data, domain)
    return findings, checked
