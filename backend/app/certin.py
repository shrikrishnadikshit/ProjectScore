"""CERT-In (Indian Computer Emergency Response Team) advisories and vulnerability notes.

CERT-In publishes no feed, so its public list pages are read at most every six hours, with a pause between
requests, plus the detail page of each new vulnerability note (for severity, affected software and CVEs).
CERT-In's copyright policy asks for permission before its material is reproduced, so we keep only facts
(ID, date, title, severity, CVE IDs, product names) and always link to the original on cert-in.org.in,
crediting CERT-In as the source. CERTIN_FEED=off disables it.
"""

from __future__ import annotations

import html as htmllib
import logging
import os
import re
import threading
import time
from datetime import date, datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Alert, CertInItem, Finding, PortfolioItem, User

logger = logging.getLogger("projectscore.certin")
router = APIRouter(prefix="/api")

BASE = "https://www.cert-in.org.in/s2cMainServlet"
LISTS = {"note": "VLNLIST02", "advisory": "PUBADVLIST02"}
DETAIL = {"note": "PUBVLNOTES01", "advisory": "PUBVLNOTES02"}
GUIDELINES_URL = f"{BASE}?pageid=GUIDLNVIEW01"
SOURCE = "CERT-In (cert-in.org.in)"
REFRESH_EVERY = timedelta(hours=6)
PAUSE = 2.0
MAX_DETAILS = 40
HEADERS = {"User-Agent": "ProjectScore-Scanner/1.0 (security ratings; fetches public CERT-In lists a few times a day)"}
_lock = threading.Lock()
_state = {"last": None, "running": False, "error": None}

_CODE = re.compile(r"VLCODE=(CI(?:VN|AD)-\d{4}-\d{3,5})", re.I)
_DATE = re.compile(r"\(?\s*([A-Z][a-z]+ \d{1,2},\s*\d{4})\s*\)?")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


def enabled() -> bool:
    return os.environ.get("CERTIN_FEED", "on").lower() != "off"


def url_for(code: str) -> str:
    kind = "note" if code.upper().startswith("CIVN") else "advisory"
    return f"{BASE}?pageid={DETAIL[kind]}&VLCODE={code}"


def _text(fragment: str) -> str:
    fragment = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", fragment)
    fragment = re.sub(r"(?i)<br\s*/?>|</(p|div|li|tr|td|h\d)>", "\n", fragment)
    return htmllib.unescape(re.sub(r"<[^>]+>", " ", fragment))


def _date(s: str) -> date | None:
    try:
        return datetime.strptime(re.sub(r"\s+", " ", s.strip()), "%B %d, %Y").date()
    except ValueError:
        return None


def parse_list(page: str) -> list[dict]:
    """Entries on a list page: each link carrying a VLCODE, then a (Month DD, YYYY) date, then the title."""
    out, seen = [], set()
    matches = list(_CODE.finditer(page))
    for i, m in enumerate(matches):
        code = m.group(1).upper()
        if code in seen:
            continue
        if i + 1 < len(matches):  # stop at the tag that holds the next entry's link
            nxt = matches[i + 1].start()
            end = max(page.rfind("<", m.end(), nxt), m.end()) if page.rfind("<", m.end(), nxt) > 0 else nxt
        else:
            end = min(len(page), m.end() + 3000)
        chunk = page[m.end():end]
        chunk = chunk[chunk.find(">") + 1:] if ">" in chunk[:400] else chunk
        text = re.sub(r"\s+", " ", _text(chunk)).strip()
        text = re.sub(rf"^.*?{re.escape(code)}", "", text, flags=re.I).strip()
        dm = _DATE.search(text)
        if not dm:
            continue
        title = text[dm.end():].strip(" -:|")
        title = re.split(r"\s{2,}|Previous|Next >>|CERT-In (?:Advisory|Vulnerability Note) CI", title)[0].strip()
        seen.add(code)
        out.append({"code": code, "kind": "note" if code.startswith("CIVN") else "advisory",
                    "issued": _date(dm.group(1)), "title": title[:300] or code})
    return out


def _section(text: str, start: str, ends: tuple[str, ...]) -> str:
    i = text.lower().find(start.lower())
    if i < 0:
        return ""
    rest = text[i + len(start):]
    cut = min([j for j in (rest.lower().find(e.lower()) for e in ends) if j >= 0] or [len(rest)])
    return rest[:cut]


def parse_detail(page: str) -> dict:
    text = _text(page)
    flat = re.sub(r"\s+", " ", text)
    sev = re.search(r"Severity Rating\s*:?\s*([A-Za-z]+)", flat)
    issued = re.search(r"Original Issue Date\s*:?\s*([A-Z][a-z]+ \d{1,2},\s*\d{4})", flat)
    affected = _section(text, "Software Affected", ("Overview", "Description", "Target Audience", "Risk Assessment"))
    products = [re.sub(r"\s+", " ", p).strip(" •-*\t") for p in affected.split("\n")]
    products = [p[:200] for p in products if len(p) > 2][:30]
    return {"severity": sev.group(1).lower() if sev else None,
            "issued": _date(issued.group(1)) if issued else None,
            "cves": sorted(set(_CVE.findall(flat)))[:100], "products": products}


def _get(client: httpx.Client, params: dict) -> str | None:
    try:
        r = client.get(BASE, params=params)
        r.raise_for_status()
        return r.text
    except httpx.HTTPError as exc:
        logger.warning("CERT-In fetch failed (%s): %s", params, exc)
        return None


def refresh(session: Session, fetch=None, today: date | None = None) -> int:
    """Store new list entries and detail new vulnerability notes. Returns how many items were added."""
    today = today or date.today()
    years = [today.year] + ([today.year - 1] if today.month == 1 else [])
    added = 0
    with httpx.Client(timeout=30.0, headers=HEADERS, follow_redirects=True) as client:
        get = fetch or (lambda params: _get(client, params))
        known = {c for (c,) in session.execute(select(CertInItem.code))}
        for kind, pageid in LISTS.items():
            for year in years:
                page = get({"pageid": pageid, "year": str(year)})
                if fetch is None:
                    time.sleep(PAUSE)
                for e in parse_list(page or ""):
                    if e["code"] in known:
                        continue
                    session.add(CertInItem(code=e["code"], kind=e["kind"], title=e["title"], issued=e["issued"],
                                           cves=[], products=[], detailed=False))
                    known.add(e["code"])
                    added += 1
        session.commit()
        todo = session.scalars(select(CertInItem).where(CertInItem.kind == "note", CertInItem.detailed.is_(False))
                               .order_by(CertInItem.issued.desc()).limit(MAX_DETAILS)).all()
        for item in todo:
            page = get({"pageid": DETAIL["note"], "VLCODE": item.code})
            if fetch is None:
                time.sleep(PAUSE)
            if not page:
                continue
            d = parse_detail(page)
            item.severity, item.cves, item.products = d["severity"], d["cves"], d["products"]
            item.issued = item.issued or d["issued"]
            item.detailed = True
            item.fetched_at = datetime.now(timezone.utc)
            session.commit()
            _alert(session, item)
    return added


def _software_words(f: Finding) -> set[str]:
    sw = (f.evidence or {}).get("software")
    if isinstance(sw, str):
        return {sw.split("/")[0].lower()}
    return set()


def affected(item: CertInItem, findings: list[Finding], names: dict[int, str]) -> list[dict]:
    """Portfolio companies with an exact CVE match ("confirmed") or the same software product ("same software")."""
    cves, exact, maybe = set(item.cves or []), set(), set()
    prod_text = " ".join(item.products or []).lower() + " " + (item.title or "").lower()
    for f in findings:
        if cves & {str(c).upper() for c in (f.evidence or {}).get("cves", []) or []}:
            exact.add(f.entity_id)
        elif any(w and len(w) >= 3 and re.search(rf"\b{re.escape(w)}\b", prod_text) for w in _software_words(f)):
            maybe.add(f.entity_id)
    maybe -= exact
    return ([{"id": i, "name": names[i], "match": "confirmed"} for i in sorted(exact, key=names.get)]
            + [{"id": i, "name": names[i], "match": "same software"} for i in sorted(maybe, key=names.get)])


def _alert(session: Session, item: CertInItem) -> None:
    if not item.cves:
        return
    findings = session.scalars(select(Finding).where(Finding.status == "open", Finding.evidence.is_not(None))).all()
    hits = {f.entity_id for f in findings if set(item.cves) & {str(c).upper() for c in (f.evidence or {}).get("cves", []) or []}}
    if not hits:
        return
    for p in session.scalars(select(PortfolioItem).where(PortfolioItem.entity_id.in_(hits))).all():
        session.add(Alert(org_id=p.org_id, entity_id=p.entity_id, kind="certin",
                          severity="critical" if item.severity in ("critical", "high") else "warning",
                          title=f"{p.entity.name}: affected by CERT-In {item.code}",
                          detail=f"{item.title}\n{url_for(item.code)}"))
    session.commit()


def refresh_async() -> None:
    if not enabled():
        return
    with _lock:
        if _state["running"] or (_state["last"] and datetime.now(timezone.utc) - _state["last"] < REFRESH_EVERY):
            return
        _state["running"] = True

    def run():
        session = db.SessionLocal()
        try:
            n = refresh(session)
            _state["error"] = None
            logger.info("CERT-In refresh added %d items", n)
        except Exception as exc:  # never break the app over an outside site
            logger.exception("CERT-In refresh failed")
            _state["error"] = str(exc)[:200]
            session.rollback()
        finally:
            session.close()
            _state["last"] = datetime.now(timezone.utc)
            _state["running"] = False

    threading.Thread(target=run, daemon=True, name="certin").start()


def _out(item: CertInItem) -> dict:
    return {"code": item.code, "kind": item.kind, "title": item.title,
            "issued": item.issued.isoformat() if item.issued else None, "severity": item.severity,
            "cves": item.cves or [], "products": item.products or [], "url": url_for(item.code)}


def by_cve(session: Session, cves: list[str]) -> dict[str, list[dict]]:
    """CERT-In items that mention each CVE (for showing CERT-In IDs next to CVEs)."""
    want, out = {c.upper() for c in cves}, {}
    if not want:
        return out
    for item in session.scalars(select(CertInItem).where(CertInItem.detailed.is_(True))).all():
        for c in set(item.cves or []) & want:
            out.setdefault(c, []).append({"code": item.code, "url": url_for(item.code), "severity": item.severity})
    return out


@router.get("/certin")
def certin_feed(days: int = 30, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    refresh_async()
    days = max(1, min(days, 365))
    cutoff = date.today() - timedelta(days=days)
    items = session.scalars(select(CertInItem).where(CertInItem.issued >= cutoff)
                            .order_by(CertInItem.issued.desc(), CertInItem.code.desc())).all()
    portfolio = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id)).all()
    names = {i.entity_id: i.entity.name for i in portfolio}
    findings = session.scalars(select(Finding).where(Finding.entity_id.in_(list(names)), Finding.status == "open")).all()
    rows = [{**_out(i), "affected": affected(i, findings, names)} for i in items]
    return {"days": days, "enabled": enabled(), "items": rows, "source": SOURCE, "guidelines_url": GUIDELINES_URL,
            "last_refresh": _state["last"].isoformat() if _state["last"] else None, "error": _state["error"],
            "affected_companies": len({a["id"] for r in rows for a in r["affected"]})}
