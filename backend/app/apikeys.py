"""Organisation API keys (read-only), managed by admins."""

import secrets

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .auth import API_KEY_PREFIX, _token_hash
from .models import ApiKey, User

router = APIRouter(prefix="/api")
MAX_KEYS = 20


def _out(k: ApiKey) -> dict:
    return {"id": k.id, "name": k.name, "prefix": k.prefix, "revoked": k.revoked,
            "created_at": k.created_at.isoformat(), "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None}


class KeyIn(BaseModel):
    name: str

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not 1 <= len(v) <= 100:
            raise ValueError("give the key a name of up to 100 characters")
        return v


@router.get("/api-keys")
def list_keys(user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> list[dict]:
    rows = session.scalars(select(ApiKey).where(ApiKey.org_id == user.org_id).order_by(ApiKey.created_at.desc())).all()
    return [_out(k) for k in rows]


@router.post("/api-keys", status_code=201)
def create_key(body: KeyIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    active = session.scalars(select(ApiKey).where(ApiKey.org_id == user.org_id, ApiKey.revoked.is_(False))).all()
    if len(active) >= MAX_KEYS:
        raise HTTPException(409, f"your organisation already has {MAX_KEYS} active keys; revoke one first")
    key = API_KEY_PREFIX + secrets.token_urlsafe(32)
    row = ApiKey(org_id=user.org_id, user_id=user.id, name=body.name, prefix=key[:10], key_hash=_token_hash(key))
    session.add(row)
    session.commit()
    return {**_out(row), "key": key}  # the only time the full key is shown


@router.post("/api-keys/{key_id}/revoke")
def revoke_key(key_id: int, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    row = session.get(ApiKey, key_id)
    if row is None or row.org_id != user.org_id:
        raise HTTPException(404, "key not found")
    row.revoked = True
    session.commit()
    return _out(row)
