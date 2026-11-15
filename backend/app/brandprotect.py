"""Brand protection: who is pretending to be a company, and what the news says about attacks on it.

- Fake websites: look-alike domains whose pages copy the company or ask for passwords (collectors/impersonation.py,
  scored under the brand factor).
- Apps: Apple App Store apps that use the company's name but are published by someone else (iTunes Search API, free).
  Google Play has no free search API, so it is not covered.
- Social profiles: the official profiles linked from the company's own home page, so fakes can be told apart,
  with each platform's impersonation report form. Social networks forbid automated searching, so we do not
  search them for fakes.
- News: articles about breaches, ransomware or cyber attacks naming the company (GDELT, free, open data).
Every item comes with where to report it for takedown.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .collectors import netsafe
from .collectors.web import USER_AGENT
from .models import Entity, Finding, User, BrandWatch

logger = logging.getLogger("projectscore.brand")
router = APIRouter(prefix="/api")

ITUNES_URL = "https://itunes.apple.com/search"
GDELT_URL = "https://api.gdeltproject.org/api/v2/doc/doc"
ATTACK_WORDS = ("breach", "ransomware", "hacked", "hackers", "cyberattack", "cyber attack", "data leak", "leaked",
                "outage", "compromised", "phishing", "malware", "stolen data")
GENERIC = {"inc", "ltd", "llc", "limited", "the", "corp", "corporation", "group", "pvt", "private", "company",
           "co", "plc", "gmbh", "technologies", "technology", "solutions", "services", "india"}
SOCIAL = [
    ("LinkedIn", re.compile(r"https?://(?:[a-z]{2,3}\.)?linkedin\.com/(?:company|school|showcase)/[A-Za-z0-9_.%-]+", re.I)),
    ("X (Twitter)", re.compile(r"https?://(?:www\.)?(?:twitter|x)\.com/(?!intent|share|home|search)[A-Za-z0-9_]{1,15}\b", re.I)),
    ("Facebook", re.compile(r"https?://(?:www\.|m\.)?facebook\.com/(?!sharer|share|dialog|plugins|tr\b)[A-Za-z0-9_.-]{3,}", re.I)),
    ("Instagram", re.compile(r"https?://(?:www\.)?instagram\.com/(?!p/|explore)[A-Za-z0-9_.]{2,30}", re.I)),
    ("YouTube", re.compile(r"https?://(?:www\.)?youtube\.com/(?:@|c/|channel/|user/)[A-Za-z0-9_.-]+", re.I)),
]
# Where to report each kind of impersonation. Checked as official report pages.
REPORT = {
    "website": [("Google Safe Browsing", "https://safebrowsing.google.com/safebrowsing/report_phish/"),
                ("Netcraft", "https://report.netcraft.com/report"),
                ("Domain registrar abuse contact", "rdap"),
                ("CERT-In (India)", "mailto:incident@cert-in.org.in")],
    "app_store": [("Apple App Store content dispute", "https://www.apple.com/legal/intellectual-property/dispute-forms/app-store/")],
    "google": [("Google legal removal (incl. Google Play)", "https://support.google.com/legal/troubleshooter/1114905")],
    "LinkedIn": [("LinkedIn Help (search \"report a fake profile\")", "https://www.linkedin.com/help/linkedin")],
    "X (Twitter)": [("X Help Center forms (impersonation)", "https://help.x.com/en/forms")],
    "Facebook": [("Facebook impersonation report", "https://www.facebook.com/help/contact/295309487309948")],
    "Instagram": [("Instagram impersonation report", "https://help.instagram.com/contact/636276399721841")],
    "YouTube": [("YouTube: report an impersonating channel", "https://support.google.com/youtube/answer/2802027")],
}
_gdelt_lock = threading.Lock()
_gdelt_last = [0.0]


def enabled() -> bool:
    return os.environ.get("BRAND_WATCH", "on").lower() != "off"


def brand_words(name: str, domain: str) -> set[str]:
    words = {w for w in re.findall(r"[a-z0-9]+", name.lower()) if w not in GENERIC and len(w) >= 3}
    return words | {domain.split(".")[0].lower()}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


# ---------- Apps ----------

def classify_apps(results: list[dict], name: str, domain: str) -> list[dict]:
    words, out = brand_words(name, domain), []
    label = domain.split(".")[0].lower()
    for r in results:
        title = r.get("trackName") or ""
        if not (set(re.findall(r"[a-z0-9]+", title.lower())) & words or label in _norm(title)):
            continue
        seller = r.get("sellerName") or r.get("artistName") or ""
        seller_url = (r.get("sellerUrl") or "").lower()
        official = (bool(seller_url) and re.search(rf"(^|[/.]){re.escape(domain)}(/|$)", re.sub(r"^https?://", "", seller_url).split("?")[0] + "/") is not None) \
            or (_norm(name) and _norm(name) in _norm(seller)) or label in _norm(seller)
        out.append({"store": "Apple App Store", "name": title, "publisher": seller, "url": r.get("trackViewUrl"),
                    "official": bool(official), "bundle": r.get("bundleId")})
    out.sort(key=lambda a: (a["official"], a["name"]))
    return out[:30]


def fetch_apps(name: str, domain: str, country: str = "us") -> list[dict] | None:
    term = domain.split(".")[0] if len(domain.split(".")[0]) >= 4 else name
    try:
        r = httpx.get(ITUNES_URL, params={"term": term, "entity": "software", "limit": 50, "country": country.lower()},
                      timeout=20.0, headers={"User-Agent": USER_AGENT})
        r.raise_for_status()
        return r.json().get("results", [])
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("app search failed for %s: %s", domain, exc)
        return None


# ---------- News ----------

def classify_news(articles: list[dict], name: str, domain: str) -> list[dict]:
    words, label, out, seen = brand_words(name, domain), domain.split(".")[0].lower(), [], set()
    full = name.lower().strip()
    for a in articles:
        title = (a.get("title") or "").strip()
        low = title.lower()
        if not (full in low or label in _norm(low) and len(label) >= 4 or domain in low):
            continue
        if not any(w in low for w in ATTACK_WORDS):
            continue
        key = _norm(title)[:80]
        if key in seen:
            continue
        seen.add(key)
        when = a.get("seendate") or ""
        try:
            when = datetime.strptime(when, "%Y%m%dT%H%M%SZ").date().isoformat()
        except ValueError:
            when = when[:10]
        out.append({"title": title, "url": a.get("url"), "source": a.get("domain"), "date": when,
                    "language": a.get("language"), "country": a.get("sourcecountry")})
    return out[:20]


def fetch_news(name: str, domain: str) -> list[dict] | None:
    label = domain.split(".")[0]
    subject = f'"{name}"' if " " in name.strip() else (f'"{name}"' if len(name) >= 4 else f'"{label}"')
    query = f'{subject} (breach OR ransomware OR hacked OR cyberattack OR "data leak")'
    with _gdelt_lock:  # GDELT asks for at most one request every five seconds
        wait = 5.5 - (time.time() - _gdelt_last[0])
        if wait > 0:
            time.sleep(wait)
        _gdelt_last[0] = time.time()
        try:
            r = httpx.get(GDELT_URL, params={"query": query, "mode": "artlist", "format": "json", "maxrecords": 75,
                                             "timespan": "6m", "sort": "datedesc"},
                          timeout=30.0, headers={"User-Agent": USER_AGENT})
            r.raise_for_status()
            return (r.json() or {}).get("articles", []) if r.text.strip().startswith("{") else []
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("news search failed for %s: %s", domain, exc)
            return None


# ---------- Social profiles ----------

def social_links(html: str) -> list[dict]:
    out, seen = [], set()
    for platform, rx in SOCIAL:
        for m in rx.finditer(html or ""):
            url = m.group(0).rstrip("/.")
            if url.lower() in seen:
                continue
            seen.add(url.lower())
            out.append({"platform": platform, "url": url})
            break  # one official profile per platform
    return out


def fetch_social(domain: str) -> list[dict] | None:
    if not netsafe.is_public_host(domain):
        return None
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True, headers={"User-Agent": USER_AGENT},
                          event_hooks={"request": [netsafe.block_private_redirects]}) as c:
            r = c.get(f"https://{domain}/")
        return social_links(r.text[:500_000])
    except httpx.HTTPError:
        return None


# ---------- Refresh and API ----------

def refresh(session: Session, entity: Entity, apps_fn=None, news_fn=None, social_fn=None) -> BrandWatch:
    row = session.scalars(select(BrandWatch).where(BrandWatch.entity_id == entity.id)).first()
    if row is None:
        row = BrandWatch(entity_id=entity.id, apps=[], news=[], social=[])
        session.add(row)
    country = (entity.country or "us") if len(entity.country or "") == 2 else "us"
    apps = (apps_fn or fetch_apps)(entity.name, entity.primary_domain, country)
    if apps is not None:
        row.apps = classify_apps(apps, entity.name, entity.primary_domain)
    news = (news_fn or fetch_news)(entity.name, entity.primary_domain)
    if news is not None:
        row.news = classify_news(news, entity.name, entity.primary_domain)
    social = (social_fn or fetch_social)(entity.primary_domain)
    if social is not None:
        row.social = social
    row.checked_at = datetime.now(timezone.utc)
    session.commit()
    return row


def refresh_after_scan(session: Session, entity: Entity) -> None:
    if not enabled():
        return
    try:
        refresh(session, entity)
    except Exception:  # brand checks must never lose a completed scan
        logger.exception("brand watch failed for %s", entity.primary_domain)
        session.rollback()


def summary(row: BrandWatch | None, findings: list[Finding]) -> dict:
    sites = [{"id": f.id, "domain": f.asset_value, "title": f.title, "severity": f.severity,
              "kind": (f.evidence or {}).get("kind"), "detail": (f.evidence or {}).get("detail"),
              "mail": f.code == "lookalike_domain_mail"}
             for f in findings if f.status == "open" and f.code.startswith(("impersonation_", "lookalike_domain_"))]
    rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    by_domain: dict[str, dict] = {}
    for site in sites:  # one row per domain: the impersonation verdict wins over the plain look-alike entry
        prev = by_domain.get(site["domain"])
        if prev is None or (site["kind"] and not prev["kind"]):
            by_domain[site["domain"]] = {**site, "mail": site["mail"] or bool(prev and prev["mail"])}
        elif prev and site["mail"]:
            prev["mail"] = True
    sites = list(by_domain.values())
    sites.sort(key=lambda s: (rank.get(s["severity"], 4), s["domain"]))
    apps = row.apps if row else []
    unofficial = [a for a in apps if not a["official"]]
    level = ("high" if any(s["severity"] == "high" for s in sites) or (row and row.news)
             else "medium" if any(s["severity"] == "medium" for s in sites) or unofficial else "low")
    return {"level": level, "fake_sites": sites, "apps": apps, "unofficial_apps": len(unofficial),
            "news": row.news if row else [], "social": row.social if row else [],
            "checked_at": row.checked_at.isoformat() if row else None, "report": REPORT,
            "sources": ["Apple iTunes Search API", "GDELT Project (gdeltproject.org)"]}


@router.get("/entities/{entity_id}/brand")
def entity_brand(entity_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    row = session.scalars(select(BrandWatch).where(BrandWatch.entity_id == entity_id)).first()
    findings = session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open")).all()
    return summary(row, findings)
