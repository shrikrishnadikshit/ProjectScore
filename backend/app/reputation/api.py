"""HTTP API for the reputation module. Every route answers 404 while REPUTATION_MODULE is off."""

from __future__ import annotations

import csv
import io
import re
import threading
from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import auth, db
from ..models import PortfolioItem, User
from . import enabled, replies, sentiment, service, sources
from .models import Brand, Mention, SearchSnapshot

router = APIRouter(prefix="/api/reputation")

MAX_BRANDS = 5
POLL_COOLDOWN = timedelta(minutes=10)
SEARCH_COOLDOWN = timedelta(hours=1)
_polling: set[int] = set()
_poll_lock = threading.Lock()


def require_enabled() -> None:
    if not enabled():
        raise HTTPException(404, "the reputation module is not switched on")


def max_brands() -> int:
    import os

    return int(os.environ.get("REPUTATION_MAX_BRANDS", str(MAX_BRANDS)))


@router.get("/config")
def config(user: User = Depends(auth.current_user)) -> dict:
    if not enabled():
        return {"enabled": False}
    return {"enabled": True, "ai_replies": replies.ai_enabled(), "google_reviews": sources.google_available(),
            "search_tracking": sources.search_available(), "max_brands": max_brands(),
            "sources": [{"key": k, "label": v[0], "kind": v[1], "available": sources.source_available(k), "needs": v[2]}
                        for k, v in sources.SOURCES.items()],
            "can_manage": user.role in ("admin", "owner")}


def _brand(session: Session, user: User, brand_id: int) -> Brand:
    b = session.get(Brand, brand_id)
    if b is None or b.org_id != user.org_id:
        raise HTTPException(404, "brand not found")
    return b


def _clean_list(values: list[str] | None) -> list[str]:
    out = []
    for v in values or []:
        v = re.sub(r"\s+", " ", (v or "")).strip()[:80]
        if len(v) >= 2 and v.lower() not in (x.lower() for x in out):
            out.append(v)
    return out[:10]


class BrandIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    keywords: list[str] = []
    exclude: list[str] = []
    sources: list[str] | None = None
    entity_id: int | None = None
    apple_app_id: str | None = None
    apple_country: str = "us"
    google_place_id: str | None = None
    search_query: str | None = Field(default=None, max_length=200)
    reply_contact: str | None = Field(default=None, max_length=200)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = re.sub(r"\s+", " ", v).strip()
        if len(v) < 2:
            raise ValueError("enter a name of at least 2 letters")
        return v

    @field_validator("apple_app_id")
    @classmethod
    def _apple(cls, v: str | None) -> str | None:
        if not v:
            return None
        m = re.search(r"(?:id)?(\d{5,12})", v.strip())
        if not m:
            raise ValueError("App Store id should be the number in the app's link, like id310633997")
        return m.group(1)

    @field_validator("apple_country")
    @classmethod
    def _country(cls, v: str) -> str:
        v = (v or "us").strip().lower()
        if not sources.COUNTRY_RE.match(v):
            raise ValueError("country should be a two-letter code such as in, us or gb")
        return v

    @field_validator("google_place_id")
    @classmethod
    def _place(cls, v: str | None) -> str | None:
        if not v:
            return None
        v = v.strip()
        if not sources.PLACE_ID_RE.match(v):
            raise ValueError("that does not look like a Google place id")
        return v


def _apply(session: Session, user: User, b: Brand, body: BrandIn) -> None:
    if body.entity_id is not None and not session.scalar(select(PortfolioItem.id).where(
            PortfolioItem.org_id == user.org_id, PortfolioItem.entity_id == body.entity_id)):
        raise HTTPException(400, "that company is not in your portfolio")
    chosen = body.sources if body.sources is not None else sources.DEFAULT_SOURCES
    bad = [s for s in chosen if s not in sources.SOURCES]
    if bad:
        raise HTTPException(400, f"unknown source: {', '.join(bad)}")
    b.name, b.keywords, b.exclude = body.name, _clean_list(body.keywords), _clean_list(body.exclude)
    b.sources = list(dict.fromkeys(chosen))
    b.entity_id, b.apple_app_id, b.apple_country = body.entity_id, body.apple_app_id, body.apple_country
    b.google_place_id = body.google_place_id
    b.search_query = (body.search_query or "").strip() or None
    b.reply_contact = (body.reply_contact or "").strip() or None


def brand_out(session: Session, b: Brand, with_summary: bool = True) -> dict:
    out = {"id": b.id, "name": b.name, "keywords": b.keywords or [], "exclude": b.exclude or [], "sources": b.sources or [],
           "entity_id": b.entity_id, "apple_app_id": b.apple_app_id, "apple_country": b.apple_country,
           "google_place_id": b.google_place_id, "search_query": b.search_query, "reply_contact": b.reply_contact,
           "source_status": b.source_status or {}, "polling": b.id in _polling,
           "last_polled_at": b.last_polled_at.isoformat() if b.last_polled_at else None,
           "created_at": b.created_at.isoformat()}
    if with_summary:
        out["summary"] = service.summary(session, b)
    return out


def mention_out(m: Mention) -> dict:
    return {"id": m.id, "source": m.source, "kind": m.kind, "url": m.url, "author": m.author, "title": m.title,
            "text": m.text, "rating": m.rating, "published_at": service.aware(m.published_at).isoformat(),
            "sentiment": m.sentiment, "label": m.label, "status": m.status, "reply_text": m.reply_text, "note": m.note}


@router.get("/brands", dependencies=[Depends(require_enabled)])
def list_brands(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> list[dict]:
    rows = session.scalars(select(Brand).where(Brand.org_id == user.org_id).order_by(Brand.name)).all()
    return [brand_out(session, b) for b in rows]


def _run_poll(brand_id: int) -> None:
    session = db.SessionLocal()
    try:
        b = session.get(Brand, brand_id)
        if b is not None:
            service.poll_brand(session, b)
    finally:
        session.close()
        with _poll_lock:
            _polling.discard(brand_id)


def _start_poll(bg: BackgroundTasks, brand_id: int) -> bool:
    with _poll_lock:
        if brand_id in _polling:
            return False
        _polling.add(brand_id)
    bg.add_task(_run_poll, brand_id)
    return True


@router.post("/brands", status_code=201, dependencies=[Depends(require_enabled)])
def create_brand(body: BrandIn, bg: BackgroundTasks, user: User = Depends(auth.require_admin),
                 session: Session = Depends(db.get_session)) -> dict:
    n = session.scalar(select(func.count()).select_from(Brand).where(Brand.org_id == user.org_id)) or 0
    if n >= max_brands():
        raise HTTPException(409, f"your plan watches up to {max_brands()} brands")
    b = Brand(org_id=user.org_id)
    _apply(session, user, b, body)
    session.add(b)
    session.commit()
    _start_poll(bg, b.id)
    return brand_out(session, b)


@router.get("/brands/{brand_id}", dependencies=[Depends(require_enabled)])
def get_brand(brand_id: int, days: int = Query(30, ge=7, le=365), user: User = Depends(auth.current_user),
              session: Session = Depends(db.get_session)) -> dict:
    b = _brand(session, user, brand_id)
    out = brand_out(session, b, with_summary=False)
    out["summary"] = service.summary(session, b, days)
    return out


@router.put("/brands/{brand_id}", dependencies=[Depends(require_enabled)])
def update_brand(brand_id: int, body: BrandIn, user: User = Depends(auth.require_admin),
                 session: Session = Depends(db.get_session)) -> dict:
    b = _brand(session, user, brand_id)
    _apply(session, user, b, body)
    session.commit()
    return brand_out(session, b)


@router.delete("/brands/{brand_id}", status_code=204, dependencies=[Depends(require_enabled)])
def delete_brand(brand_id: int, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> Response:
    b = _brand(session, user, brand_id)
    session.delete(b)
    session.commit()
    return Response(status_code=204)


@router.post("/brands/{brand_id}/poll", status_code=202, dependencies=[Depends(require_enabled)])
def poll(brand_id: int, bg: BackgroundTasks, user: User = Depends(auth.current_user),
         session: Session = Depends(db.get_session)) -> dict:
    b = _brand(session, user, brand_id)
    last = service.aware(b.last_polled_at)
    if last and service.now() - last < POLL_COOLDOWN:
        mins = int((POLL_COOLDOWN - (service.now() - last)).total_seconds() // 60) + 1
        raise HTTPException(429, f"checked a moment ago. Try again in {mins} minute{'s' if mins > 1 else ''}.")
    if not _start_poll(bg, b.id):
        raise HTTPException(409, "already checking")
    return {"status": "started"}


@router.get("/brands/{brand_id}/mentions", dependencies=[Depends(require_enabled)])
def list_mentions(brand_id: int, label: str | None = None, source: str | None = None, status: str | None = None,
                  kind: str | None = None, q: str | None = Query(None, max_length=100), days: int = Query(30, ge=1, le=365),
                  limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                  user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    b = _brand(session, user, brand_id)
    stmt = select(Mention).where(Mention.brand_id == b.id, Mention.published_at >= service.now() - timedelta(days=days))
    for col, val in ((Mention.label, label), (Mention.source, source), (Mention.status, status), (Mention.kind, kind)):
        if val:
            stmt = stmt.where(col == val)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Mention.text).like(like), func.lower(Mention.title).like(like)))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = session.scalars(stmt.order_by(Mention.published_at.desc(), Mention.id.desc()).limit(limit).offset(offset)).all()
    return {"total": total, "mentions": [mention_out(m) for m in rows]}


def _mention(session: Session, user: User, mention_id: int) -> Mention:
    m = session.get(Mention, mention_id)
    if m is None or m.brand.org_id != user.org_id:
        raise HTTPException(404, "mention not found")
    return m


class MentionPatch(BaseModel):
    status: str | None = Field(default=None, pattern="^(new|seen|replied|ignored)$")
    note: str | None = Field(default=None, max_length=1000)
    reply_text: str | None = Field(default=None, max_length=4000)
    label: str | None = Field(default=None, pattern="^(positive|neutral|negative)$")


@router.patch("/mentions/{mention_id}", dependencies=[Depends(require_enabled)])
def update_mention(mention_id: int, body: MentionPatch, user: User = Depends(auth.current_user),
                   session: Session = Depends(db.get_session)) -> dict:
    m = _mention(session, user, mention_id)
    for field in ("status", "note", "reply_text"):
        val = getattr(body, field)
        if val is not None:
            setattr(m, field, val or None if field != "status" else val)
    if body.label is not None and body.label != m.label:  # a person correcting the machine
        m.label = body.label
        m.sentiment = {"positive": 0.5, "neutral": 0.0, "negative": -0.5}[body.label]
    session.commit()
    return mention_out(m)


class ReplyIn(BaseModel):
    tone: str | None = Field(default=None, max_length=60)


@router.post("/mentions/{mention_id}/suggest-reply", dependencies=[Depends(require_enabled)])
def suggest_reply(mention_id: int, body: ReplyIn, user: User = Depends(auth.current_user),
                  session: Session = Depends(db.get_session)) -> dict:
    m = _mention(session, user, mention_id)
    text = " ".join(filter(None, [m.title, m.text]))
    label = SOURCES_LABEL.get(m.source, m.source)
    return replies.suggest(m.brand.name, label, m.label, m.rating, text, m.author, m.brand.reply_contact, body.tone)


SOURCES_LABEL = {k: v[0] for k, v in sources.SOURCES.items()} | {"import": "an imported review", "manual": "a review site"}


class MentionIn(BaseModel):
    text: str = Field(min_length=2, max_length=4000)
    title: str | None = Field(default=None, max_length=500)
    author: str | None = Field(default=None, max_length=200)
    url: str | None = Field(default=None, max_length=1000, pattern=r"^https?://")
    rating: int | None = Field(default=None, ge=1, le=5)


@router.post("/brands/{brand_id}/mentions", status_code=201, dependencies=[Depends(require_enabled)])
def add_mention(brand_id: int, body: MentionIn, user: User = Depends(auth.current_user),
                session: Session = Depends(db.get_session)) -> dict:
    b = _brand(session, user, brand_id)
    import secrets

    new = service.ingest(session, b, [{"source": "manual", "kind": "review" if body.rating else "mention",
                                       "external_id": secrets.token_hex(8), "url": body.url, "author": body.author,
                                       "title": body.title, "text": body.text, "rating": body.rating,
                                       "published_at": service.now()}], check_terms=False)
    session.commit()
    service.check_alerts(session, b, new)
    return mention_out(new[0])


class ImportIn(BaseModel):
    csv: str = Field(max_length=5_000_000)


@router.post("/brands/{brand_id}/import", dependencies=[Depends(require_enabled)])
def import_mentions(brand_id: int, body: ImportIn, user: User = Depends(auth.current_user),
                    session: Session = Depends(db.get_session)) -> dict:
    b = _brand(session, user, brand_id)
    try:
        return service.import_csv(session, b, body.csv)
    except (ValueError, csv.Error) as exc:
        raise HTTPException(400, str(exc)) from exc


@router.get("/brands/{brand_id}/export.csv", dependencies=[Depends(require_enabled)])
def export_mentions(brand_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> Response:
    b = _brand(session, user, brand_id)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["date", "source", "kind", "author", "rating", "sentiment", "label", "status", "title", "text", "url", "reply"])
    for m in session.scalars(select(Mention).where(Mention.brand_id == b.id).order_by(Mention.published_at.desc())):
        row = [service.aware(m.published_at).isoformat(), m.source, m.kind, m.author, m.rating, m.sentiment, m.label,
               m.status, m.title, m.text, m.url, m.reply_text]
        # Stop spreadsheet apps from running cell contents as formulas.
        w.writerow([("'" + c) if isinstance(c, str) and c[:1] in "=+-@\t\r" else c for c in row])
    name = re.sub(r"[^A-Za-z0-9]+", "-", b.name).strip("-").lower() or "brand"
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{name}-mentions.csv"'})


@router.get("/brands/{brand_id}/google", dependencies=[Depends(require_enabled)])
def google_reviews(brand_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    b = _brand(session, user, brand_id)
    if not sources.google_available():
        raise HTTPException(404, "Google reviews are not set up")
    if not b.google_place_id:
        raise HTTPException(400, "add the Google place id for this brand first")
    try:
        data = sources.fetch_google(b.google_place_id)
    except Exception as exc:
        raise HTTPException(502, f"Google did not answer: {str(exc)[:200]}") from exc
    for r in data["reviews"]:
        r["sentiment"], r["label"] = sentiment.score(r.get("text"), r.get("rating"))
    return data


@router.get("/brands/{brand_id}/search", dependencies=[Depends(require_enabled)])
def search_results(brand_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    b = _brand(session, user, brand_id)
    snaps = session.scalars(select(SearchSnapshot).where(SearchSnapshot.brand_id == b.id)
                            .order_by(SearchSnapshot.taken_at.desc()).limit(26)).all()
    return {"available": sources.search_available(), **service.search_summary(list(snaps))}


@router.post("/brands/{brand_id}/search", dependencies=[Depends(require_enabled)])
def take_search(brand_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    b = _brand(session, user, brand_id)
    if not sources.search_available():
        raise HTTPException(404, "search tracking is not set up")
    last = session.scalar(select(func.max(SearchSnapshot.taken_at)).where(SearchSnapshot.brand_id == b.id))
    if last and service.now() - service.aware(last) < SEARCH_COOLDOWN:
        raise HTTPException(429, "search results were checked within the last hour")
    try:
        service.take_search_snapshot(session, b)
    except Exception as exc:
        raise HTTPException(502, f"the search provider did not answer: {str(exc)[:200]}") from exc
    return search_results(brand_id, user, session)
