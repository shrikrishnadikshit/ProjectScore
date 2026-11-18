"""Core data objects from BRS Section 5.2 (subset needed for v1)."""

from datetime import date, datetime, timezone

from sqlalchemy import JSON, Date, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
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


class Alert(Base):
    """A notice for one organisation about a company in its portfolio (score drop or new serious issue)."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(30))  # score_drop, new_serious
    severity: Mapped[str] = mapped_column(String(20), default="warning")  # warning, critical
    title: Mapped[str] = mapped_column(String(300))
    detail: Mapped[str | None] = mapped_column(String(4000))
    read: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Questionnaire(Base):
    """A security questionnaire sent by an organisation to a vendor, answered through a private link."""

    __tablename__ = "questionnaires"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    recipient_email: Mapped[str] = mapped_column(String(320))
    recipient_name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(20), default="sent")  # sent, in_progress, submitted, reviewed
    answers: Mapped[dict] = mapped_column(JSON, default=dict)
    reviewer_note: Mapped[str | None] = mapped_column(String(2000))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RiskInput(Base):
    """An organisation's inputs for estimating a company's cyber risk in rupees."""

    __tablename__ = "risk_inputs"
    __table_args__ = (UniqueConstraint("org_id", "entity_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"))
    revenue_crore: Mapped[float | None] = mapped_column(Float)
    sensitivity: Mapped[str] = mapped_column(String(20), default="standard")  # low, standard, high
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ApiKey(Base):
    """A read-only API key for an organisation's own systems (stored as a hash, shown once)."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(100))
    prefix: Mapped[str] = mapped_column(String(16))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    revoked: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Incident(Base):
    """A real security incident at a rated company, recorded by the owner to test whether scores predict them."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    occurred_on: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    kind: Mapped[str] = mapped_column(String(40))  # breach, ransomware, outage, fraud, other
    description: Mapped[str] = mapped_column(String(2000))
    source_url: Mapped[str | None] = mapped_column(String(1000))
    score_before: Mapped[int | None] = mapped_column(Integer)
    recorded_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AdvisoryRequest(Base):
    """A customer's request for expert help fixing findings (an advisory or remediation service lead)."""

    __tablename__ = "advisory_requests"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int | None] = mapped_column(ForeignKey("entities.id", ondelete="SET NULL"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    service: Mapped[str] = mapped_column(String(40))  # fix_guidance, remediation_support, vendor_followup, assessment
    finding_codes: Mapped[list] = mapped_column(JSON, default=list)
    message: Mapped[str | None] = mapped_column(String(4000))
    preferred_contact: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(20), default="new")  # new, in_progress, done, declined
    owner_note: Mapped[str | None] = mapped_column(String(4000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class CveInfo(Base):
    """Cached severity data for a CVE: CVSS from NIST's NVD, EPSS exploit probability from FIRST."""

    __tablename__ = "cve_info"

    cve_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    cvss: Mapped[float | None] = mapped_column(Float)
    cvss_version: Mapped[str | None] = mapped_column(String(10))
    cvss_severity: Mapped[str | None] = mapped_column(String(20))
    cvss_vector: Mapped[str | None] = mapped_column(String(200))
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    description: Mapped[str | None] = mapped_column(String(1000))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CodeReview(Base):
    """A source code review: the code is scanned with free tools and only the findings are kept."""

    __tablename__ = "code_reviews"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    requested_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    name: Mapped[str] = mapped_column(String(200))
    source_type: Mapped[str] = mapped_column(String(10))  # git, zip
    source: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued, running, done, failed
    error: Mapped[str | None] = mapped_column(String(1000))
    results: Mapped[list] = mapped_column(JSON, default=list)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class VendorDetection(Base):
    """Third-party services a company visibly relies on (its vendors, i.e. your fourth parties), from public DNS."""

    __tablename__ = "vendor_detections"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), unique=True, index=True)
    vendors: Mapped[list] = mapped_column(JSON, default=list)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VendorShare(Base):
    """A private link that lets a vendor see the issues found on its systems and reply to each one."""

    __tablename__ = "vendor_shares"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    recipient_email: Mapped[str] = mapped_column(String(320))
    recipient_name: Mapped[str | None] = mapped_column(String(255))
    message: Mapped[str | None] = mapped_column(String(2000))
    responses: Mapped[dict] = mapped_column(JSON, default=dict)  # finding id -> {status, comment, at}
    revoked: Mapped[bool] = mapped_column(default=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_viewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_rescan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class VendorCertificate(Base):
    """A certification or audit report a vendor holds (ISO 27001, SOC 2...), recorded by the customer."""

    __tablename__ = "vendor_certificates"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(30))
    reference: Mapped[str | None] = mapped_column(String(200))   # certificate number or report name
    issuer: Mapped[str | None] = mapped_column(String(200))      # certification body or audit firm
    scope: Mapped[str | None] = mapped_column(String(1000))
    issued_on: Mapped[date | None] = mapped_column(Date)
    expires_on: Mapped[date | None] = mapped_column(Date)
    exceptions: Mapped[int | None] = mapped_column(Integer)      # SOC 2 exceptions / audit nonconformities
    note: Mapped[str | None] = mapped_column(String(2000))
    reminded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AssetProfile(Base):
    """How important a system is, and who hosts it where (refreshed at each scan)."""

    __tablename__ = "asset_profiles"
    __table_args__ = (UniqueConstraint("entity_id", "asset"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    asset: Mapped[str] = mapped_column(String(255))          # host name or IP address
    kind: Mapped[str] = mapped_column(String(10))            # host, ip
    value: Mapped[str] = mapped_column(String(10))           # high, medium, low
    reasons: Mapped[list] = mapped_column(JSON, default=list)
    ip: Mapped[str | None] = mapped_column(String(64))
    asn: Mapped[str | None] = mapped_column(String(20))
    provider: Mapped[str | None] = mapped_column(String(255))
    country: Mapped[str | None] = mapped_column(String(2))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RiskPolicy(Base):
    """An organisation's minimum security requirements for vendors, per tier."""

    __tablename__ = "risk_policies"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), unique=True, index=True)
    rules: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OrgSettings(Base):
    """Per-organisation preferences: home country, display currency and local breach cost."""

    __tablename__ = "org_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), unique=True, index=True)
    country: Mapped[str] = mapped_column(String(2), default="IN")
    currency: Mapped[str] = mapped_column(String(3), default="INR")
    breach_cost_usd_m: Mapped[float | None] = mapped_column(Float)  # override, in millions of US dollars
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BrandWatch(Base):
    """Brand protection results for a company: apps using its name, attack news and official social profiles."""

    __tablename__ = "brand_watch"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), unique=True, index=True)
    apps: Mapped[list] = mapped_column(JSON, default=list)
    news: Mapped[list] = mapped_column(JSON, default=list)
    social: Mapped[list] = mapped_column(JSON, default=list)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CertInItem(Base):
    """A CERT-In advisory (CIAD) or vulnerability note (CIVN): identifiers and facts only, with a link to the full text."""

    __tablename__ = "certin_items"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(10))  # advisory, note
    title: Mapped[str] = mapped_column(String(300))
    issued: Mapped[date | None] = mapped_column(Date)
    severity: Mapped[str | None] = mapped_column(String(20))
    cves: Mapped[list] = mapped_column(JSON, default=list)
    products: Mapped[list] = mapped_column(JSON, default=list)
    detailed: Mapped[bool] = mapped_column(default=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VendorOnboarding(Base):
    """A vendor's path from intake to approval: business context, inherent risk, tier, decision and next review."""

    __tablename__ = "vendor_onboardings"
    __table_args__ = (UniqueConstraint("org_id", "entity_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    stage: Mapped[str] = mapped_column(String(20), default="intake")  # intake, assessment, review, approved, conditional, rejected
    intake: Mapped[dict] = mapped_column(JSON, default=dict)
    inherent_score: Mapped[int | None] = mapped_column(Integer)
    tier: Mapped[int | None] = mapped_column(Integer)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decision_note: Mapped[str | None] = mapped_column(String(2000))
    next_review: Mapped[date | None] = mapped_column(Date)
    history: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class QuestionnaireProfile(Base):
    """Which questions a smart questionnaire asks, why, and the AI-drafted answers from the vendor's documents."""

    __tablename__ = "questionnaire_profiles"

    id: Mapped[int] = mapped_column(primary_key=True)
    questionnaire_id: Mapped[int] = mapped_column(ForeignKey("questionnaires.id", ondelete="CASCADE"), unique=True, index=True)
    question_ids: Mapped[list] = mapped_column(JSON, default=list)
    reasons: Mapped[dict] = mapped_column(JSON, default=dict)
    drafts: Mapped[dict] = mapped_column(JSON, default=dict)
    documents: Mapped[list] = mapped_column(JSON, default=list)  # names and sizes only; files are not kept
    ai_runs: Mapped[int] = mapped_column(Integer, default=0)


class OrgIntegration(Base):
    """A connection to Slack or Jira for one organisation. Secrets are write-only through the API."""

    __tablename__ = "org_integrations"
    __table_args__ = (UniqueConstraint("org_id", "kind"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # slack, jira
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    secret: Mapped[str | None] = mapped_column(String(500))
    enabled: Mapped[bool] = mapped_column(default=True)
    last_error: Mapped[str | None] = mapped_column(String(500))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CveIntel(Base):
    """Extra facts about a CVE from open sources: the official CVE record (CVE.org, with CISA's exploitation
    assessment), GitHub Security Advisories, and CIRCL Vulnerability-Lookup sightings."""

    __tablename__ = "cve_intel"

    cve_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    record: Mapped[dict] = mapped_column(JSON, default=dict)  # CVE.org: assigner, title, products, CISA SSVC
    github: Mapped[list] = mapped_column(JSON, default=list)  # GHSA ids, severity, packages, patched versions
    sightings: Mapped[dict] = mapped_column(JSON, default=dict)  # CIRCL: counts by type
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CisaAdvisory(Base):
    """A CISA cybersecurity or ICS advisory from its public RSS feeds (US Government work, free to reuse)."""

    __tablename__ = "cisa_advisories"

    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str] = mapped_column(String(500), unique=True, index=True)
    code: Mapped[str | None] = mapped_column(String(40), index=True)  # e.g. ICSA-26-301-01, AA26-120A
    kind: Mapped[str] = mapped_column(String(10))  # ics, general
    title: Mapped[str] = mapped_column(String(400))
    published: Mapped[date | None] = mapped_column(Date)
    cves: Mapped[list] = mapped_column(JSON, default=list)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UserMfa(Base):
    """Two-step login with an authenticator app (TOTP, RFC 6238). Recovery codes are stored hashed."""

    __tablename__ = "user_mfa"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    secret: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(default=False)
    recovery: Mapped[list] = mapped_column(JSON, default=list)
    last_step: Mapped[int] = mapped_column(Integer, default=0)  # blocks reuse of a code
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OrgSecurity(Base):
    """An organisation's sign-in rules."""

    __tablename__ = "org_security"

    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    require_mfa: Mapped[bool] = mapped_column(default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    """Who did what, when. Each row carries a hash of the previous one, so edits or deletions are detectable."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    org_id: Mapped[int | None] = mapped_column(Integer, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer)
    actor: Mapped[str | None] = mapped_column(String(320))
    action: Mapped[str] = mapped_column(String(60))
    target: Mapped[str | None] = mapped_column(String(300))
    status: Mapped[int | None] = mapped_column(Integer)
    ip: Mapped[str | None] = mapped_column(String(64))
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class RemediationTask(Base):
    """One issue type at one company, assigned to someone with a due date, closed when a rescan confirms the fix."""

    __tablename__ = "remediation_tasks"
    __table_args__ = (UniqueConstraint("org_id", "entity_id", "code"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    code: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(15))
    assignee_id: Mapped[int | None] = mapped_column(Integer)
    assignee_email: Mapped[str | None] = mapped_column(String(320))  # e.g. the vendor's contact
    due: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), default="open")  # open, in_progress, fixed, verified, accepted, wont_fix
    note: Mapped[str | None] = mapped_column(String(2000))
    history: Mapped[list] = mapped_column(JSON, default=list)
    created_by: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RiskAcceptance(Base):
    """A decision to live with a risk for a time: a whole vendor or one issue type, with approver and expiry."""

    __tablename__ = "risk_acceptances"

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    code: Mapped[str | None] = mapped_column(String(80))  # None = the vendor as a whole
    reason: Mapped[str] = mapped_column(String(2000))
    controls: Mapped[str | None] = mapped_column(String(2000))  # compensating controls
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, approved, rejected, expired, revoked
    requested_by: Mapped[int | None] = mapped_column(Integer)
    approver_id: Mapped[int | None] = mapped_column(Integer)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_on: Mapped[date] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class OrgPreferences(Base):
    """Per-organisation thresholds: fix deadlines by severity and when to raise alerts."""

    __tablename__ = "org_preferences"

    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VendorProfile(Base):
    """What a vendor does for the organisation, and its offboarding checklist (BRS TPRM-001, TPRM-009)."""

    __tablename__ = "vendor_profiles"
    __table_args__ = (UniqueConstraint("org_id", "entity_id"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    org_id: Mapped[int] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    contract_end: Mapped[date | None] = mapped_column(Date)
    offboarding: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
