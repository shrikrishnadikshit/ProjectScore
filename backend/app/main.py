import logging
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, Response as RawResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db, scheduler
from .models import Entity, Finding, PortfolioItem, Score, User
from .scan import NothingAssessed, scan_entity
from .disputes import router as disputes_router
from .freereport import router as freereport_router
from .frameworks import router as frameworks_router
from .alerts import router as alerts_router
from .benchmark import router as benchmark_router
from .questionnaires import router as questionnaires_router
from .risk import router as risk_router
from .apikeys import router as apikeys_router
from .sso import router as sso_router
from .incidents import router as incidents_router
from .remediation import router as remediation_router
from .advisory import router as advisory_router
from .attack import techniques as attack_techniques
from . import account, ai, assets, brandprotect, darkweb, attackpaths, certificates, orgsettings, policy, codereview, ransomware, threatevents, vendors, vendorshare
from .active import fail_interrupted_scans, router as active_router, update_templates_async
from .optout import is_opted_out, router as optout_router
from .users_api import router as users_router
from . import reputation

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# Minimum time between scans of the same entity, to keep scanning polite (BRS 4.4).
SCAN_COOLDOWN = timedelta(minutes=10)

logger = logging.getLogger("projectscore")

# Error tracking: set SENTRY_DSN on Render to report crashes to Sentry. Personal data (cookies,
# request bodies, user emails) is not sent.
if os.environ.get("SENTRY_DSN"):
    import sentry_sdk

    sentry_sdk.init(dsn=os.environ["SENTRY_DSN"], send_default_pii=False, traces_sample_rate=0.0,
                    environment=os.environ.get("SENTRY_ENVIRONMENT", "production"))


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.Base.metadata.create_all(db.engine)
    session = db.SessionLocal()
    try:
        auth.bootstrap_admin(session)
        fail_interrupted_scans(session)
        codereview.fail_interrupted(session)
    finally:
        session.close()
    scheduler.start()
    reputation.start()
    update_templates_async()
    yield
    scheduler.stop()
    reputation.stop()


app = FastAPI(title="ProjectScore API", version="0.2.0", lifespan=lifespan)
api = APIRouter(prefix="/api")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; "
       "base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # Cross-site request check: browsers send Origin on cross-site POSTs, so a request from another
    # site is refused even though the session cookie is already SameSite=Lax.
    if request.method in UNSAFE_METHODS and request.url.path.startswith("/api/"):
        origin = request.headers.get("origin")
        if origin and origin != "null" and urlsplit(origin).netloc != request.headers.get("host"):
            return JSONResponse({"detail": "cross-site request refused"}, status_code=403)
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if auth.COOKIE_SECURE:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


# ---------- Auth ----------

class LoginIn(BaseModel):
    email: str
    password: str


_user_out = auth.user_out


@api.get("/health")
def health() -> dict:
    return {"status": "ok"}


@api.post("/auth/login")
def login(body: LoginIn, response: Response, session: Session = Depends(db.get_session)) -> dict:
    key = body.email.strip().lower()
    if auth.throttle.blocked(key):
        raise HTTPException(429, "too many failed attempts; try again in 15 minutes")
    user = auth.authenticate(session, body.email, body.password)
    if user is None:
        auth.throttle.fail(key)
        raise HTTPException(401, "email or password is incorrect")
    auth.throttle.reset(key)
    auth.start_session(session, user, response)
    return _user_out(user)


@api.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response, session: Session = Depends(db.get_session)) -> Response:
    auth.end_session(session, request, response)
    response.status_code = 204
    return response


@api.get("/auth/me")
def me(user: User = Depends(auth.current_user)) -> dict:
    return _user_out(user)


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str


@api.post("/auth/password", status_code=204)
def change_password(body: PasswordChangeIn, user: User = Depends(auth.current_user),
                    session: Session = Depends(db.get_session)) -> Response:
    if not auth.verify_password(body.current_password, user.password_hash):
        raise HTTPException(403, "current password is incorrect")
    try:
        auth.set_password(session, user, body.new_password)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return Response(status_code=204)


# ---------- Portfolio and ratings ----------

class EntityIn(BaseModel):
    name: str
    primary_domain: str
    industry: str | None = None
    country: str | None = None
    tier: int = 3

    @field_validator("primary_domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        v = v.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
        if not DOMAIN_RE.match(v):
            raise ValueError("not a valid domain")
        return v

    @field_validator("tier")
    @classmethod
    def _tier(cls, v: int) -> int:
        if v not in (1, 2, 3):
            raise ValueError("tier must be 1, 2 or 3")
        return v


def _entity_out(e: Entity, item: PortfolioItem, latest: Score | None) -> dict:
    return {"id": e.id, "name": e.name, "primary_domain": e.primary_domain, "industry": e.industry,
            "country": e.country, "tier": item.tier,
            "score": latest.overall if latest else None, "grade": latest.grade if latest else None,
            "scanned_at": latest.created_at.isoformat() if latest else None}


def _latest(session: Session, entity_id: int) -> Score | None:
    return session.scalars(select(Score).where(Score.entity_id == entity_id)
                           .order_by(Score.created_at.desc(), Score.id.desc())).first()


def _portfolio_item(session: Session, user: User, entity_id: int) -> PortfolioItem:
    """Entities outside the user's portfolio are reported as not found, not forbidden."""
    item = session.scalars(select(PortfolioItem).where(
        PortfolioItem.org_id == user.org_id, PortfolioItem.entity_id == entity_id)).first()
    if item is None:
        raise HTTPException(404, "entity not found")
    return item


@api.post("/entities", status_code=201)
def add_entity(body: EntityIn, user: User = Depends(auth.current_user),
               session: Session = Depends(db.get_session)) -> dict:
    entity = session.scalars(select(Entity).where(Entity.primary_domain == body.primary_domain)).first()
    if entity is None:
        entity = Entity(name=body.name, primary_domain=body.primary_domain, industry=body.industry,
                        country=body.country)
        session.add(entity)
        session.flush()
    elif session.scalars(select(PortfolioItem).where(
            PortfolioItem.org_id == user.org_id, PortfolioItem.entity_id == entity.id)).first():
        raise HTTPException(409, "this company is already in your portfolio")
    item = PortfolioItem(org_id=user.org_id, entity_id=entity.id, tier=body.tier)
    session.add(item)
    session.commit()
    return _entity_out(entity, item, _latest(session, entity.id))


MAX_IMPORT_ROWS = 500


class ImportIn(BaseModel):
    csv: str
    scan: bool = True


def _import_scans(entity_ids: list[int]) -> None:
    """First scans for imported companies, one at a time so a big import does not overload the server."""
    import time

    for entity_id in entity_ids:
        _scan_job(entity_id)
        time.sleep(2)


@api.post("/entities/import")
def import_entities(body: ImportIn, tasks: BackgroundTasks, user: User = Depends(auth.require_admin),
                    session: Session = Depends(db.get_session)) -> dict:
    """Adds companies from CSV text with columns name and domain, and optionally tier and industry."""
    import csv
    import io

    from .benchmark import INDUSTRIES

    if len(body.csv) > 1_000_000:
        raise HTTPException(413, "the file is too large (limit 1 MB)")
    rows = list(csv.reader(io.StringIO(body.csv.lstrip("\ufeff"))))
    rows = [r for r in rows if any(c.strip() for c in r)]
    if not rows:
        raise HTTPException(422, "the file is empty")
    header = [c.strip().lower() for c in rows[0]]
    aliases = {"name": ("name", "company", "company name", "vendor", "vendor name"),
               "domain": ("domain", "website", "primary_domain", "primary domain", "url"),
               "tier": ("tier", "criticality"), "industry": ("industry", "sector")}
    col = {k: next((header.index(a) for a in names if a in header), None) for k, names in aliases.items()}
    if col["domain"] is None:
        if len(header) >= 2 and DOMAIN_RE.match(header[1].removeprefix("https://").removeprefix("http://").split("/")[0]):
            col = {"name": 0, "domain": 1, "tier": 2 if len(header) > 2 else None, "industry": None}  # no header row
        else:
            raise HTTPException(422, "add a header row with at least the columns name and domain")
    else:
        rows = rows[1:]
    if len(rows) > MAX_IMPORT_ROWS:
        raise HTTPException(422, f"import at most {MAX_IMPORT_ROWS} companies at a time")
    mine = set(session.scalars(select(PortfolioItem.entity_id).where(PortfolioItem.org_id == user.org_id)))
    added, skipped, to_scan = [], [], []

    def cell(r, k):
        i = col.get(k)
        return r[i].strip() if i is not None and i < len(r) else ""

    for n, r in enumerate(rows, start=1):
        domain = cell(r, "domain")
        tier_text = cell(r, "tier")
        try:
            data = EntityIn(name=cell(r, "name") or domain, primary_domain=domain,
                            tier=int(tier_text) if tier_text else 3)
        except (ValueError, TypeError) as exc:
            skipped.append({"row": n, "value": domain or cell(r, "name"), "reason": "not a valid domain or tier"
                            if "domain" in str(exc) or "tier" in str(exc) or "int" in str(exc) else str(exc)[:100]})
            continue
        industry = cell(r, "industry")
        industry = next((i for i in INDUSTRIES if i.lower() == industry.lower()), None) if industry else None
        entity = session.scalars(select(Entity).where(Entity.primary_domain == data.primary_domain)).first()
        if entity is None:
            entity = Entity(name=data.name[:255], primary_domain=data.primary_domain, industry=industry)
            session.add(entity)
            session.flush()
        elif entity.id in mine:
            skipped.append({"row": n, "value": data.primary_domain, "reason": "already in your portfolio"})
            continue
        session.add(PortfolioItem(org_id=user.org_id, entity_id=entity.id, tier=data.tier))
        mine.add(entity.id)
        added.append({"id": entity.id, "name": entity.name, "domain": entity.primary_domain})
        if _latest(session, entity.id) is None and not is_opted_out(session, entity.primary_domain):
            to_scan.append(entity.id)
    session.commit()
    if body.scan and to_scan:
        tasks.add_task(_import_scans, to_scan)
    return {"added": added, "skipped": skipped, "scans_queued": len(to_scan) if body.scan else 0}


@api.get("/entities")
def list_entities(user: User = Depends(auth.current_user),
                  session: Session = Depends(db.get_session)) -> list[dict]:
    items = session.scalars(select(PortfolioItem).where(PortfolioItem.org_id == user.org_id)).all()
    rows = [_entity_out(i.entity, i, _latest(session, i.entity_id)) for i in items]
    return sorted(rows, key=lambda r: r["name"].lower())


@api.get("/entities/{entity_id}")
def get_entity(entity_id: int, user: User = Depends(auth.current_user),
               session: Session = Depends(db.get_session)) -> dict:
    item = _portfolio_item(session, user, entity_id)
    latest = _latest(session, entity_id)
    out = _entity_out(item.entity, item, latest)
    out["factors"] = latest.factors if latest else {}
    order = {"domain": 0, "subdomain": 1, "netblock": 2, "ip": 3}
    out["assets"] = [{"type": a.type, "value": a.value}
                     for a in sorted(item.entity.assets, key=lambda a: (order.get(a.type, 9), a.value))]
    out["opted_out"] = is_opted_out(session, item.entity.primary_domain)
    asset_values = assets.values(session, entity_id)
    out["findings"] = [
        {"id": f.id, "risk_factor": f.risk_factor, "code": f.code, "title": f.title, "severity": f.severity,
         "asset": f.asset_value, "status": f.status, "evidence": f.evidence,
         "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat(),
         "attack": attack_techniques(f.code), "asset_value": asset_values.get(f.asset_value),
         "priority": (assets.priority(f.severity, asset_values.get(f.asset_value)) if f.severity != "info" else 4)}
        for f in session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open"))
    ]
    from . import cves as cve_data
    from .patching import summary

    open_findings = session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open")).all()
    out["cves"] = cve_data.lookup(session, cve_data.cves_in(open_findings))

    out["patching"] = summary(session.scalars(select(Finding).where(Finding.entity_id == entity_id)).all())
    return out


@api.delete("/entities/{entity_id}", status_code=204)
def remove_entity(entity_id: int, user: User = Depends(auth.current_user),
                  session: Session = Depends(db.get_session)) -> Response:
    """Removes the company from this organisation's portfolio only; shared scan data is kept."""
    session.delete(_portfolio_item(session, user, entity_id))
    session.commit()
    return Response(status_code=204)


@api.get("/entities/{entity_id}/scores")
def score_history(entity_id: int, user: User = Depends(auth.current_user),
                  session: Session = Depends(db.get_session)) -> list[dict]:
    _portfolio_item(session, user, entity_id)
    return [{"overall": s.overall, "grade": s.grade, "model_version": s.model_version,
             "created_at": s.created_at.isoformat(), "trace": s.trace}
            for s in session.scalars(select(Score).where(Score.entity_id == entity_id).order_by(Score.created_at))]


@api.get("/entities/{entity_id}/report.pdf")
def entity_report(entity_id: int, user: User = Depends(auth.current_user),
                  session: Session = Depends(db.get_session)) -> RawResponse:
    from .report import build_pdf  # imported lazily: only needed when a report is requested

    data = get_entity(entity_id, user, session)
    history = score_history(entity_id, user, session)
    pdf = build_pdf(data, history, user.org.name)
    slug = re.sub(r"[^a-z0-9]+", "-", data["primary_domain"].lower()).strip("-")
    return RawResponse(pdf, media_type="application/pdf",
                       headers={"Content-Disposition": f'attachment; filename="projectscore-{slug}.pdf"'})


def _scan_job(entity_id: int) -> None:
    session = db.SessionLocal()
    try:
        scan_entity(session, session.get(Entity, entity_id))
    except NothingAssessed as exc:
        logger.warning("scan skipped: %s", exc)
    except Exception:
        logger.exception("scan failed for entity %s", entity_id)
    finally:
        session.close()


@api.post("/entities/{entity_id}/scan", status_code=202)
def start_scan(entity_id: int, tasks: BackgroundTasks, user: User = Depends(auth.current_user),
               session: Session = Depends(db.get_session)) -> dict:
    item = _portfolio_item(session, user, entity_id)
    if is_opted_out(session, item.entity.primary_domain):
        raise HTTPException(409, "this company has opted out of scanning, so it cannot be rescanned")
    latest = _latest(session, entity_id)
    if latest is not None:
        created = latest.created_at if latest.created_at.tzinfo else latest.created_at.replace(tzinfo=timezone.utc)
        wait = created + SCAN_COOLDOWN - datetime.now(timezone.utc)
        if wait.total_seconds() > 0:
            raise HTTPException(429, f"this company was scanned recently; try again in {int(wait.total_seconds() // 60) + 1} minutes")
    tasks.add_task(_scan_job, entity_id)
    return {"status": "scan started"}


app.include_router(api)
app.include_router(users_router)
app.include_router(optout_router)
app.include_router(active_router)
app.include_router(disputes_router)
app.include_router(freereport_router)
app.include_router(frameworks_router)
app.include_router(alerts_router)
app.include_router(benchmark_router)
app.include_router(questionnaires_router)
app.include_router(risk_router)
app.include_router(apikeys_router)
app.include_router(sso_router)
app.include_router(incidents_router)
app.include_router(remediation_router)
app.include_router(advisory_router)
app.include_router(codereview.router)
app.include_router(vendors.router)
app.include_router(vendorshare.router)
app.include_router(ransomware.router)
app.include_router(threatevents.router)
app.include_router(certificates.router)
app.include_router(assets.router)
app.include_router(policy.router)
app.include_router(orgsettings.router)
app.include_router(account.router)
app.include_router(attackpaths.router)
app.include_router(ai.router)
app.include_router(darkweb.router)
app.include_router(brandprotect.router)
app.include_router(reputation.router)

# Serve the built web app (frontend/dist) from the same server in production.
DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        if path.startswith("api/"):
            raise HTTPException(404, "not found")
        return FileResponse(DIST / "index.html")
