import logging
import re
from contextlib import asynccontextmanager

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db
from .models import Entity, Finding, Score
from .scan import NothingAssessed, scan_entity

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")



@asynccontextmanager
async def lifespan(_: FastAPI):
    db.Base.metadata.create_all(db.engine)
    yield


logger = logging.getLogger("projectscore")
app = FastAPI(title="ProjectScore API", version="0.1.0", lifespan=lifespan)
api = APIRouter(prefix="/api")


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


def _entity_out(e: Entity, latest: Score | None) -> dict:
    return {"id": e.id, "name": e.name, "primary_domain": e.primary_domain, "industry": e.industry,
            "country": e.country, "tier": e.tier,
            "score": latest.overall if latest else None, "grade": latest.grade if latest else None,
            "scanned_at": latest.created_at.isoformat() if latest else None}


def _latest(session: Session, entity_id: int) -> Score | None:
    return session.scalars(select(Score).where(Score.entity_id == entity_id)
                           .order_by(Score.created_at.desc(), Score.id.desc())).first()


def _get(session: Session, entity_id: int) -> Entity:
    entity = session.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(404, "entity not found")
    return entity


@api.get("/health")
def health() -> dict:
    return {"status": "ok"}


@api.post("/entities", status_code=201)
def create_entity(body: EntityIn, session: Session = Depends(db.get_session)) -> dict:
    if session.scalars(select(Entity).where(Entity.primary_domain == body.primary_domain)).first():
        raise HTTPException(409, "an entity with this domain already exists")
    entity = Entity(**body.model_dump())
    session.add(entity)
    session.commit()
    return _entity_out(entity, None)


@api.get("/entities")
def list_entities(session: Session = Depends(db.get_session)) -> list[dict]:
    return [_entity_out(e, _latest(session, e.id)) for e in session.scalars(select(Entity).order_by(Entity.name))]


@api.get("/entities/{entity_id}")
def get_entity(entity_id: int, session: Session = Depends(db.get_session)) -> dict:
    entity = _get(session, entity_id)
    latest = _latest(session, entity_id)
    out = _entity_out(entity, latest)
    out["factors"] = latest.factors if latest else {}
    out["findings"] = [
        {"id": f.id, "risk_factor": f.risk_factor, "code": f.code, "title": f.title, "severity": f.severity,
         "asset": f.asset_value, "status": f.status, "evidence": f.evidence,
         "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat()}
        for f in session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open"))
    ]
    return out


@api.get("/entities/{entity_id}/scores")
def score_history(entity_id: int, session: Session = Depends(db.get_session)) -> list[dict]:
    _get(session, entity_id)
    return [{"overall": s.overall, "grade": s.grade, "model_version": s.model_version,
             "created_at": s.created_at.isoformat(), "trace": s.trace}
            for s in session.scalars(select(Score).where(Score.entity_id == entity_id).order_by(Score.created_at))]


def _scan_job(entity_id: int) -> None:
    session = db.SessionLocal()
    try:
        scan_entity(session, session.get(Entity, entity_id))
    except NothingAssessed as exc:
        logger.warning("scan skipped: %s", exc)
    finally:
        session.close()


@api.post("/entities/{entity_id}/scan", status_code=202)
def start_scan(entity_id: int, tasks: BackgroundTasks, session: Session = Depends(db.get_session)) -> dict:
    _get(session, entity_id)
    tasks.add_task(_scan_job, entity_id)
    return {"status": "scan started"}


app.include_router(api)

# Serve the built web app (frontend/dist) from the same server in production.
DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str) -> FileResponse:
        return FileResponse(DIST / "index.html")
