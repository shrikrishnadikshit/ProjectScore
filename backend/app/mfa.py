"""Two-step login (MFA) with an authenticator app, BRS GEN-003 / NFR-008.

Standard TOTP (RFC 6238: SHA-1, 30-second steps, 6 digits), so any authenticator app works (Google
Authenticator, Microsoft Authenticator, 1Password, Authy). Each user also gets 10 one-time recovery codes,
stored hashed. Admins can require MFA for everyone in their organisation. Sign-in through Google or
Microsoft relies on that provider's own MFA.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import auth, db
from .models import OrgSecurity, User, UserMfa

router = APIRouter(prefix="/api")
ISSUER = "ProjectScore"
STEP = 30
CHALLENGE_SECONDS = 300


# ---------- TOTP ----------

def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret: str) -> bytes:
    return base64.b32decode(secret + "=" * (-len(secret) % 8))


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def check_code(secret: str, code: str, last_step: int = 0, now: float | None = None) -> int | None:
    """The time step the code belongs to (one step of clock drift allowed), or None. Reused steps fail."""
    code = "".join(c for c in (code or "") if c.isdigit())
    if len(code) != 6:
        return None
    current = int((now if now is not None else time.time()) // STEP)
    for step in (current - 1, current, current + 1):
        if step > last_step and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def uri(secret: str, email: str) -> str:
    return (f"otpauth://totp/{quote(ISSUER)}:{quote(email)}?secret={secret}&issuer={quote(ISSUER)}"
            f"&algorithm=SHA1&digits=6&period={STEP}")


def _hash(code: str) -> str:
    return hashlib.sha256(code.replace("-", "").lower().encode()).hexdigest()


def recovery_codes() -> list[str]:
    return [f"{secrets.token_hex(3)}-{secrets.token_hex(3)}" for _ in range(10)]


# ---------- state ----------

def row_for(session: Session, user: User) -> UserMfa | None:
    return session.get(UserMfa, user.id)


def enabled(session: Session, user: User) -> bool:
    row = row_for(session, user)
    return bool(row and row.enabled)


def org_requires(session: Session, org_id: int) -> bool:
    row = session.get(OrgSecurity, org_id)
    return bool(row and row.require_mfa)


def verify(session: Session, user: User, code: str) -> bool:
    """Accept an authenticator code or an unused recovery code."""
    row = row_for(session, user)
    if not row or not row.enabled:
        return False
    step = check_code(row.secret, code, row.last_step or 0)
    if step is not None:
        row.last_step = step
        session.commit()
        return True
    h = _hash(code.strip())
    if h in (row.recovery or []):
        row.recovery = [r for r in row.recovery if r != h]
        session.commit()
        return True
    return False


# ---------- login challenge ----------

def challenge_for(user: User) -> str:
    expires = int(time.time()) + CHALLENGE_SECONDS
    msg = f"{user.id}.{expires}"
    sig = hmac.new(auth.secret_key().encode(), f"mfa:{msg}".encode(), hashlib.sha256).hexdigest()
    return f"{msg}.{sig}"


def user_from_challenge(session: Session, challenge: str) -> User | None:
    try:
        uid, expires, sig = challenge.split(".")
        good = hmac.new(auth.secret_key().encode(), f"mfa:{uid}.{expires}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(good, sig) or int(expires) < time.time():
            return None
        user = session.get(User, int(uid))
    except (ValueError, TypeError):
        return None
    return user if user and user.active else None


# ---------- API ----------

class CodeIn(BaseModel):
    code: str


class ChallengeIn(BaseModel):
    challenge: str
    code: str


class DisableIn(BaseModel):
    password: str
    code: str


class PolicyIn(BaseModel):
    require_mfa: bool


@router.post("/auth/mfa")
def complete_login(body: ChallengeIn, response: Response, session: Session = Depends(db.get_session)) -> dict:
    user = user_from_challenge(session, body.challenge)
    if user is None:
        raise HTTPException(401, "sign-in expired; please enter your password again")
    key = f"mfa:{user.id}"
    if auth.throttle.blocked(key):
        raise HTTPException(429, "too many wrong codes; try again in 15 minutes")
    if not verify(session, user, body.code):
        auth.throttle.fail(key)
        raise HTTPException(401, "that code is not right; check the time on your phone and try again")
    auth.throttle.reset(key)
    auth.start_session(session, user, response)
    from .audit import record

    record(session, user, "sign_in", "mfa")
    return auth.user_out(user)


@router.get("/auth/mfa/status")
def status(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    row = row_for(session, user)
    return {"enabled": bool(row and row.enabled), "recovery_left": len(row.recovery or []) if row and row.enabled else 0,
            "org_requires": org_requires(session, user.org_id)}


@router.post("/auth/mfa/setup")
def setup(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    row = row_for(session, user)
    if row and row.enabled:
        raise HTTPException(409, "two-step login is already on")
    if row is None:
        row = UserMfa(user_id=user.id, secret=new_secret(), recovery=[])
        session.add(row)
    else:
        row.secret = new_secret()
    session.commit()
    return {"secret": row.secret, "uri": uri(row.secret, user.email)}


@router.post("/auth/mfa/enable")
def enable(body: CodeIn, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    row = row_for(session, user)
    if row is None or row.enabled:
        raise HTTPException(409, "start the setup first")
    step = check_code(row.secret, body.code)
    if step is None:
        raise HTTPException(422, "that code is not right; check the time on your phone and try again")
    codes = recovery_codes()
    row.enabled, row.last_step, row.recovery = True, step, [_hash(c) for c in codes]
    session.commit()
    from .audit import record

    record(session, user, "mfa_enabled", user.email)
    return {"recovery_codes": codes}


@router.post("/auth/mfa/disable", status_code=204)
def disable(body: DisableIn, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> Response:
    if org_requires(session, user.org_id):
        raise HTTPException(409, "your organisation requires two-step login")
    if not auth.verify_password(body.password, user.password_hash) or not verify(session, user, body.code):
        raise HTTPException(403, "password or code is not right")
    row = row_for(session, user)
    session.delete(row)
    session.commit()
    from .audit import record

    record(session, user, "mfa_disabled", user.email)
    return Response(status_code=204)


@router.get("/org/security")
def get_policy(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    return {"require_mfa": org_requires(session, user.org_id)}


@router.put("/org/security")
def set_policy(body: PolicyIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    if body.require_mfa and not enabled(session, user):
        raise HTTPException(409, "turn on two-step login for your own account first")
    row = session.get(OrgSecurity, user.org_id)
    if row is None:
        row = OrgSecurity(org_id=user.org_id)
        session.add(row)
    row.require_mfa, row.updated_at = body.require_mfa, datetime.now(timezone.utc)
    session.commit()
    from .audit import record

    record(session, user, "policy_changed", f"require_mfa={body.require_mfa}")
    return {"require_mfa": row.require_mfa}


def gate(request: Request, session: Session, user: User) -> None:
    """Block a password-only user whose organisation requires MFA, except on the pages that set it up."""
    path = request.url.path
    if path.startswith("/api/auth/") or request.headers.get("authorization", "").lower().startswith("bearer "):
        return
    if org_requires(session, user.org_id) and not enabled(session, user):
        raise HTTPException(403, "mfa_setup_required")
