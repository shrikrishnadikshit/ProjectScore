"""Core data objects from BRS Section 5.2 (subset needed for v1)."""

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Entity(Base):
    __tablename__ = "entities"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    primary_domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    industry: Mapped[str | None] = mapped_column(String(100))
    country: Mapped[str | None] = mapped_column(String(2))
    tier: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    assets: Mapped[list["Asset"]] = relationship(back_populates="entity", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="entity", cascade="all, delete-orphan")
    scores: Mapped[list["Score"]] = relationship(back_populates="entity", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), index=True)
    type: Mapped[str] = mapped_column(String(30))  # domain, subdomain, ip, certificate
    value: Mapped[str] = mapped_column(String(255))
    attribution_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    entity: Mapped[Entity] = relationship(back_populates="assets")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), index=True)
    asset_value: Mapped[str] = mapped_column(String(255))
    risk_factor: Mapped[str] = mapped_column(String(50), index=True)
    code: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(15))
    detection_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="open")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    entity: Mapped[Entity] = relationship(back_populates="findings")


class Score(Base):
    __tablename__ = "scores"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), index=True)
    overall: Mapped[int] = mapped_column(Integer)
    grade: Mapped[str] = mapped_column(String(1))
    model_version: Mapped[str] = mapped_column(String(20))
    factors: Mapped[dict] = mapped_column(JSON)
    trace: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    entity: Mapped[Entity] = relationship(back_populates="scores")


class Organization(Base):
    """A customer tenant. Each organisation has its own portfolio and users."""

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="member")  # member, admin
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    org: Mapped[Organization] = relationship()


class SessionToken(Base):
    """Server-side login session. Only a hash of the cookie value is stored."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped[User] = relationship()


class PortfolioItem(Base):
    """An organisation monitoring an entity. Entities and their scans are shared;
    the portfolio (and tier) is private to each organisation."""

    __tablename__ = "portfolio_items"
    __table_args__ = (UniqueConstraint("org_id", "entity_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id"), index=True)
    tier: Mapped[int] = mapped_column(Integer, default=3)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    entity: Mapped[Entity] = relationship()


class OptOutRequest(Base):
    """A request from a domain owner not to be scanned (BRS 4.4). Approved requests exclude
    the domain and all its subdomains from scanning."""

    __tablename__ = "opt_out_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    contact_email: Mapped[str] = mapped_column(String(255))
    organisation: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(String(2000))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, approved, rejected
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class DomainVerification(Base):
    """Proof that an organisation controls a domain (DNS TXT record). Required before in-depth scans."""

    __tablename__ = "domain_verifications"
    __table_args__ = (UniqueConstraint("org_id", "domain"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    domain: Mapped[str] = mapped_column(String(255))
    token: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ActiveScan(Base):
    """A consent-based in-depth scan (BRS 4.1: active testing only for proven, authorised assets).
    The authorisation statement and who gave it are stored with the scan as the audit record."""

    __tablename__ = "active_scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id"), index=True)
    domain: Mapped[str] = mapped_column(String(255))
    targets: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued, running, done, failed
    requested_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    authoriser_name: Mapped[str] = mapped_column(String(255))
    authoriser_title: Mapped[str] = mapped_column(String(255))
    authorisation_text: Mapped[str] = mapped_column(String(4000))
    authorised_from_ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    results: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str | None] = mapped_column(String(2000))


class Dispute(Base):
    """A challenge to a finding (BRS 7.5). Accepted disputes mark the finding as a false positive and
    keep the same finding from reappearing on later scans."""

    __tablename__ = "disputes"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id"), index=True)
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("findings.id"), index=True)
    code: Mapped[str | None] = mapped_column(String(80))
    asset_value: Mapped[str | None] = mapped_column(String(255))
    domain: Mapped[str | None] = mapped_column(String(255))  # for public disputes without a finding
    submitted_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    contact_email: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(4000))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, accepted, rejected
    reviewer_note: Mapped[str | None] = mapped_column(String(2000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FreeReport(Base):
    """A one-time rating summary requested from the public free-report page (a sales lead)."""

    __tablename__ = "free_reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    contact_email: Mapped[str] = mapped_column(String(320))
    name: Mapped[str | None] = mapped_column(String(255))
    organisation: Mapped[str | None] = mapped_column(String(255))
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(20), default="scanning")  # scanning, ready, failed
    message: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
