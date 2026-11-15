"""Collecting mentions, scoring reputation and raising crisis alerts."""

from __future__ import annotations

import csv
import hashlib
import io
import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import Alert
from . import sentiment, sources
from .models import Brand, Mention, SearchSnapshot

logger = logging.getLogger("projectscore.reputation")


def now() -> datetime:
    return datetime.now(timezone.utc)


def aware(d: datetime | None) -> datetime | None:
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)


def crisis_min() -> int:
    return int(os.environ.get("REPUTATION_CRISIS_MIN", "5"))


def crisis_factor() -> float:
    return float(os.environ.get("REPUTATION_CRISIS_FACTOR", "3"))


def retention_days() -> int:
    return int(os.environ.get("REPUTATION_RETENTION_DAYS", "365"))


def terms(brand: Brand) -> list[str]:
    seen, out = set(), []
    for t in [brand.name, *(brand.keywords or [])]:
        t = (t or "").strip()
        if t and t.lower() not in seen:
            seen.add(t.lower())
            out.append(t)
    return out[:10]


def relevant(item: dict, brand: Brand, check_terms: bool = True) -> bool:
    """Search APIs match loosely. Keep a mention only if it names the brand, and drop excluded words.
    Reviews come from the brand's own app page, so they always count."""
    body = " ".join(filter(None, [item.get("title"), item.get("text")])).lower()
    if any(x and x.lower() in body for x in (brand.exclude or [])):
        return False
    if item.get("kind") == "review" or not check_terms:
        return True
    return any(t.lower() in body for t in terms(brand))


def ingest(session: Session, brand: Brand, items: list[dict], check_terms: bool = True) -> list[Mention]:
    """Store new items, skipping ones already seen. Returns only the new mentions."""
    if not items:
        return []
    keys = {(i["source"], i["external_id"]) for i in items}
    existing = set(session.execute(select(Mention.source, Mention.external_id).where(
        Mention.brand_id == brand.id, Mention.external_id.in_([k[1] for k in keys]))).all())
    new = []
    for item in items:
        key = (item["source"], item["external_id"])
        if key in existing or not relevant(item, brand, check_terms):
            continue
        existing.add(key)
        rating = item.get("rating")
        if rating is not None:
            rating = max(1, min(5, int(rating)))
        value, lab = sentiment.score(" ".join(filter(None, [item.get("title"), item.get("text")])), rating)
        m = Mention(brand_id=brand.id, source=item["source"], kind=item.get("kind") or "mention",
                    external_id=item["external_id"][:300], url=(item.get("url") or None) and item["url"][:1000],
                    author=(item.get("author") or None) and str(item["author"])[:200],
                    title=(item.get("title") or None) and item["title"][:500], text=item.get("text"),
                    rating=rating, published_at=aware(item.get("published_at")) or now(),
                    sentiment=value, label=lab)
        session.add(m)
        new.append(m)
    session.flush()
    return new


def _status(brand: Brand, key: str, ok: bool, count: int = 0, error: str | None = None) -> None:
    st = dict(brand.source_status or {})
    st[key] = {"ok": ok, "at": now().isoformat(), "count": count, "error": (error or None) and error[:300]}
    brand.source_status = st


def poll_brand(session: Session, brand: Brand) -> dict:
    """Fetch every switched-on source for one brand, store new mentions, and raise alerts."""
    since = aware(brand.last_polled_at) or (now() - sources.LOOKBACK_FIRST_POLL)
    since = min(since, now() - timedelta(hours=1))  # small overlap so nothing falls between polls
    found: list[Mention] = []
    for key in brand.sources or []:
        if not sources.source_available(key):
            continue
        try:
            if key == "apple":
                if not brand.apple_app_id:
                    continue
                items = sources.fetch_apple(brand.apple_app_id, brand.apple_country or "us")
            else:
                items = sources.FETCHERS[key](terms(brand), since)
            new = ingest(session, brand, items)
            found.extend(new)
            _status(brand, key, True, len(new))
        except Exception as exc:  # one broken source must not stop the others
            logger.warning("reputation source %s failed for brand %s: %s", key, brand.id, exc)
            _status(brand, key, False, error=str(exc))
    brand.last_polled_at = now()
    session.commit()
    alerts = check_alerts(session, brand, found)
    return {"new": len(found), "alerts": len(alerts)}


def check_alerts(session: Session, brand: Brand, new: list[Mention]) -> list[Alert]:
    out = []
    t = now()
    day_ago, week_ago = t - timedelta(hours=24), t - timedelta(days=8)
    rows = session.scalars(select(Mention).where(Mention.brand_id == brand.id, Mention.label == "negative",
                                                 Mention.published_at >= week_ago)).all()
    last_day = [m for m in rows if aware(m.published_at) >= day_ago]
    before = [m for m in rows if aware(m.published_at) < day_ago]
    baseline = len(before) / 7.0
    last_crisis = aware(brand.last_crisis_at)
    if (len(last_day) >= crisis_min() and len(last_day) >= crisis_factor() * max(baseline, 1.0)
            and (last_crisis is None or last_crisis < day_ago)):
        sample = sorted(last_day, key=lambda m: m.sentiment)[:5]
        out.append(Alert(org_id=brand.org_id, entity_id=None, kind="reputation_crisis", severity="critical",
                         title=f"{brand.name}: {len(last_day)} negative mentions in the last 24 hours "
                               f"(usually about {baseline:.0f} a day)",
                         detail="\n".join(f"{m.source}: {(m.title or m.text or '')[:160]}" for m in sample)))
        brand.last_crisis_at = t
    bad_reviews = [m for m in new if m.kind == "review" and m.rating is not None and m.rating <= 2]
    if bad_reviews:
        out.append(Alert(org_id=brand.org_id, entity_id=None, kind="reputation_review", severity="warning",
                         title=f"{brand.name}: {len(bad_reviews)} new review{'s' if len(bad_reviews) > 1 else ''} "
                               f"with 1 or 2 stars",
                         detail="\n".join(f"{m.rating} stars: {(m.title or m.text or '')[:160]}" for m in bad_reviews[:5])))
    if out:
        session.add_all(out)
        session.commit()
    return out


def summary(session: Session, brand: Brand, days: int = 30) -> dict:
    """Reputation score 0 to 100, trend by day, and breakdowns for the dashboard."""
    t = now()
    start = t - timedelta(days=days)
    rows = session.scalars(select(Mention).where(Mention.brand_id == brand.id, Mention.published_at >= start)).all()
    prev = session.scalars(select(Mention).where(Mention.brand_id == brand.id, Mention.published_at >= start - timedelta(days=days),
                                                 Mention.published_at < start)).all()
    counts = {k: sum(1 for m in rows if m.label == k) for k in ("positive", "neutral", "negative")}
    by_source: dict[str, dict] = {}
    for m in rows:
        s = by_source.setdefault(m.source, {"source": m.source, "total": 0, "positive": 0, "neutral": 0, "negative": 0})
        s["total"] += 1
        s[m.label] += 1
    daily = []
    for i in range(days, -1, -1):
        d = (t - timedelta(days=i)).date()
        day = [m for m in rows if aware(m.published_at).date() == d]
        daily.append({"date": d.isoformat(), "positive": sum(m.label == "positive" for m in day),
                      "neutral": sum(m.label == "neutral" for m in day), "negative": sum(m.label == "negative" for m in day)})
    ratings = [m.rating for m in rows if m.rating]
    return {"score": score(rows), "previous_score": score(prev), "total": len(rows), **counts,
            "average_rating": round(sum(ratings) / len(ratings), 2) if ratings else None, "reviews": len(ratings),
            "by_source": sorted(by_source.values(), key=lambda s: -s["total"]), "daily": daily,
            "open": sum(1 for m in rows if m.status == "new" and m.label == "negative"), "days": days}


MIN_FOR_SCORE = 5


def score(rows: list[Mention]) -> int | None:
    """0 to 100. 60 percent from the balance of positive and negative mentions, 40 percent from star
    ratings when there are any. None when there are too few mentions to say anything."""
    if len(rows) < MIN_FOR_SCORE:
        return None
    net = sum(m.sentiment for m in rows) / len(rows)  # -1..1
    mention_part = 50 * (1 + net)
    ratings = [m.rating for m in rows if m.rating]
    if ratings:
        star_part = (sum(ratings) / len(ratings) - 1) / 4 * 100
        return round(0.6 * mention_part + 0.4 * star_part)
    return round(mention_part)


def take_search_snapshot(session: Session, brand: Brand, country: str | None = None) -> SearchSnapshot:
    query = brand.search_query or brand.name
    results = sources.fetch_search(query, country)
    for r in results:
        value, lab = sentiment.score(" ".join(filter(None, [r.get("title"), r.get("snippet")])))
        r["sentiment"], r["label"] = value, lab
        r["owned"] = bool(r.get("domain") and brand.entity_id and _owned(session, brand, r["domain"]))
    snap = SearchSnapshot(brand_id=brand.id, query=query, results=results)
    session.add(snap)
    session.commit()
    return snap


def _owned(session: Session, brand: Brand, domain: str) -> bool:
    from ..models import Entity

    e = session.get(Entity, brand.entity_id)
    return bool(e and (domain == e.primary_domain or domain.endswith("." + e.primary_domain)))


def search_summary(snaps: list[SearchSnapshot]) -> dict:
    if not snaps:
        return {"latest": None, "history": []}
    latest = snaps[0]
    prev = snaps[1] if len(snaps) > 1 else None
    prev_ranks = {r["url"]: r["rank"] for r in (prev.results if prev else [])}
    results = [{**r, "previous_rank": prev_ranks.get(r["url"]), "new": prev is not None and r["url"] not in prev_ranks}
               for r in latest.results]
    history = [{"taken_at": s.taken_at.isoformat(), "negative_top10": sum(1 for r in s.results[:10] if r.get("label") == "negative"),
                "owned_top10": sum(1 for r in s.results[:10] if r.get("owned"))} for s in reversed(snaps)]
    return {"latest": {"id": latest.id, "query": latest.query, "taken_at": latest.taken_at.isoformat(), "results": results,
                       "negative_top10": history[-1]["negative_top10"], "owned_top10": history[-1]["owned_top10"]},
            "history": history}


IMPORT_LIMIT = 5000


def import_csv(session: Session, brand: Brand, text: str) -> dict:
    """Columns (header row, any order): text (required), date, source, author, rating, title, url.
    Lets customers bring reviews from places we cannot read directly (Google Business Profile exports,
    Trustpilot, Glassdoor, support tickets)."""
    reader = csv.DictReader(io.StringIO(text))
    fields = {(f or "").strip().lower(): f for f in (reader.fieldnames or [])}
    if "text" not in fields:
        raise ValueError("the CSV needs a 'text' column")
    items, skipped = [], 0
    for n, row in enumerate(reader, start=2):
        if n - 1 > IMPORT_LIMIT:
            raise ValueError(f"at most {IMPORT_LIMIT} rows per import")
        get = lambda k: (row.get(fields[k]) or "").strip() if k in fields else ""  # noqa: E731
        body = get("text")
        if not body:
            skipped += 1
            continue
        rating = get("rating")
        try:
            rating = int(float(rating)) if rating else None
        except ValueError:
            rating = None
        src = (get("source") or "import").lower()[:30]
        digest = hashlib.sha256(f"{body}|{get('date')}|{get('author')}".encode()).hexdigest()[:16]
        items.append({"source": "import", "kind": "review" if rating else "mention",
                      "external_id": f"{src}:{get('url') or ''}:{digest}"[:300],
                      "url": get("url") if get("url").startswith(("http://", "https://")) else None,
                      "author": get("author") or None, "title": (get("title") or src.title())[:500], "text": body[:4000],
                      "rating": rating, "published_at": sources._dt(get("date")) if get("date") else None})
    # Imported rows are the customer's own data, so the brand-name check does not apply.
    new = ingest(session, brand, items, check_terms=False)
    session.commit()
    return {"imported": len(new), "skipped": skipped, "duplicates": len(items) - len(new)}


def purge_old(session: Session) -> int:
    cutoff = now() - timedelta(days=retention_days())
    n = session.execute(delete(Mention).where(Mention.published_at < cutoff)).rowcount or 0
    session.execute(delete(SearchSnapshot).where(SearchSnapshot.taken_at < cutoff))
    session.commit()
    return n
