"""Tables for the reputation module. Kept apart from app/models.py so the module can be switched off cleanly."""

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db import Base
from ..models import utcnow


class Brand(Base):
    """A brand, product or person an organisation wants to watch online."""

    __tablename__ = "rep_brands"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(120))
    keywords: Mapped[list] = mapped_column(JSON, default=list)  # extra search terms, e.g. product names
    exclude: Mapped[list] = mapped_column(JSON, default=list)  # drop mentions containing these words
    sources: Mapped[list] = mapped_column(JSON, default=list)  # source keys switched on for this brand
    apple_app_id: Mapped[str | None] = mapped_column(String(20))
    apple_country: Mapped[str] = mapped_column(String(2), default="us")
    google_place_id: Mapped[str | None] = mapped_column(String(200))
    search_query: Mapped[str | None] = mapped_column(String(200))
    reply_contact: Mapped[str | None] = mapped_column(String(200))  # shown in suggested replies, e.g. support@...
    source_status: Mapped[dict] = mapped_column(JSON, default=dict)
    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_crisis_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    mentions: Mapped[list["Mention"]] = relationship(back_populates="brand", cascade="all, delete-orphan",
                                                     passive_deletes=True)
    snapshots: Mapped[list["SearchSnapshot"]] = relationship(cascade="all, delete-orphan", passive_deletes=True)


class Mention(Base):
    """One review, post, comment or news article about a brand."""

    __tablename__ = "rep_mentions"
    __table_args__ = (UniqueConstraint("brand_id", "source", "external_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    brand_id: Mapped[int] = mapped_column(ForeignKey("rep_brands.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(30))  # news, hackernews, bluesky, reddit, apple, import, manual
    kind: Mapped[str] = mapped_column(String(15), default="mention")  # mention, review, news
    external_id: Mapped[str] = mapped_column(String(300))
    url: Mapped[str | None] = mapped_column(String(1000))
    author: Mapped[str | None] = mapped_column(String(200))
    title: Mapped[str | None] = mapped_column(String(500))
    text: Mapped[str | None] = mapped_column(Text)
    rating: Mapped[int | None] = mapped_column(Integer)  # 1 to 5 stars, reviews only
    published_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    sentiment: Mapped[float] = mapped_column(Float, default=0.0)  # -1 (very negative) to +1 (very positive)
    label: Mapped[str] = mapped_column(String(10), default="neutral")  # positive, neutral, negative
    status: Mapped[str] = mapped_column(String(15), default="new")  # new, seen, replied, ignored
    reply_text: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(String(1000))

    brand: Mapped[Brand] = relationship(back_populates="mentions")


class SearchSnapshot(Base):
    """The top web search results for a brand at one point in time, each marked positive, neutral or negative."""

    __tablename__ = "rep_search_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    brand_id: Mapped[int] = mapped_column(ForeignKey("rep_brands.id", ondelete="CASCADE"), index=True)
    query: Mapped[str] = mapped_column(String(200))
    results: Mapped[list] = mapped_column(JSON, default=list)
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
