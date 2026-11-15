import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Entity, Finding, PortfolioItem, Score, User
from .scan import NothingAssessed, scan_entity

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
# Minimum time between scans of the same entity, to keep scanning polite (BRS 4.4).
SCAN_COOLDOWN = timedelta(minutes=10)

logger = logging.getLogger("projectscore")


@asynccontextmanager
async def lifespan(_: FastAPI):
    db.Base.metadata.create_all(db.engine)
    session = db.SessionLocal()
    try:
        auth.bootstrap_admin(session)
    finally:
        session.close()
    yield


app = FastAPI(title="ProjectScore API", version="0.2.0", lifespan=lifespan)
api = APIRouter(prefix="/api")


# ---------- Auth ----------

class LoginIn(BaseModel):
    email: str
    password: str


class UserIn(BaseModel):
    email: str
    password: str
    name: str | None = None
    role: str = "member"


def _user_out(user: User) -> dict:
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role,
            "organization": user.org.name}


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


@api.post("/users", status_code=201)
def invite_user(body: UserIn, admin: User = Depends(auth.require_admin),
                session: Session = Depends(db.get_session)) -> dict:
    """Admins add users to their own organisation."""
    if body.role not in ("member", "admin"):
        raise HTTPException(422, "role must be member or admin")
    try:
        user = auth.create_user(session, admin.org.name, body.email, body.password, body.role, body.name)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    return _user_out(user)


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
    out["findings"] = [
        {"id": f.id, "risk_factor": f.risk_factor, "code": f.code, "title": f.title, "severity": f.severity,
         "asset": f.asset_value, "status": f.status, "evidence": f.evidence,
         "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat()}
        for f in session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open"))
    ]
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
    _portfolio_item(session, user, entity_id)
    latest = _latest(session, entity_id)
    if latest is not None:
        created = latest.created_at if latest.created_at.tzinfo else latest.created_at.replace(tzinfo=timezone.utc)
        wait = created + SCAN_COOLDOWN - datetime.now(timezone.utc)
        if wait.total_seconds() > 0:
            raise HTTPException(429, f"this company was scanned recently; try again in {int(wait.total_seconds() // 60) + 1} minutes")
    tasks.add_task(_scan_job, entity_id)
    return {"status": "scan started"}


app.include_router(api)

# Serve the built web app (frontend/dist) from the same server in production.
DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        if path.startswith("api/"):
            raise HTTPException(404, "not found")
        return FileResponse(DIST / "index.html")
