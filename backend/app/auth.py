"""Password hashing, login sessions and the current-user dependency.

Uses only the standard library: scrypt for passwords, random tokens for sessions.
"""

import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db
from .models import Organization, SessionToken, User

COOKIE_NAME = "ps_session"
SESSION_DAYS = 7
MIN_PASSWORD_LENGTH = 12
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}

# Cookies are Secure unless explicitly running locally over plain HTTP.
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() != "false"


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), **_SCRYPT)
    return hmac.compare_digest(digest.hex(), digest_hex)


# A dummy hash so failed logins for unknown emails take as long as for known ones.
_DUMMY_HASH = hash_password(secrets.token_hex(8))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class LoginThrottle:
    """Blocks an email after repeated failures (in memory; per server process)."""

    def __init__(self, max_failures: int = 5, window_seconds: int = 900):
        self.max_failures, self.window = max_failures, window_seconds
        self._failures: dict[str, list[float]] = {}

    def blocked(self, key: str) -> bool:
        now = time.monotonic()
        recent = [t for t in self._failures.get(key, []) if now - t < self.window]
        self._failures[key] = recent
        return len(recent) >= self.max_failures

    def fail(self, key: str) -> None:
        self._failures.setdefault(key, []).append(time.monotonic())

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)


throttle = LoginThrottle()


def authenticate(session: Session, email: str, password: str) -> User | None:
    user = session.scalars(select(User).where(User.email == email.strip().lower())).first()
    if user is None or not user.active:
        verify_password(password, _DUMMY_HASH)
        return None
    return user if verify_password(password, user.password_hash) else None


def start_session(session: Session, user: User, response: Response) -> None:
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
    session.add(SessionToken(token_hash=_token_hash(token), user_id=user.id, expires_at=expires))
    session.commit()
    response.set_cookie(COOKIE_NAME, token, max_age=SESSION_DAYS * 86400, httponly=True,
                        secure=COOKIE_SECURE, samesite="lax", path="/")


def end_session(session: Session, request: Request, response: Response) -> None:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        row = session.scalars(select(SessionToken).where(SessionToken.token_hash == _token_hash(token))).first()
        if row:
            session.delete(row)
            session.commit()
    response.delete_cookie(COOKIE_NAME, path="/")


API_KEY_PREFIX = "ps_"


def _api_key_user(request: Request, session: Session, header: str) -> User:
    """Read-only access with an organisation API key: `Authorization: Bearer ps_...`."""
    from .models import ApiKey

    key = header[7:].strip()
    row = session.scalars(select(ApiKey).where(ApiKey.key_hash == _token_hash(key))).first() if key.startswith(API_KEY_PREFIX) else None
    if row is None or row.revoked:
        raise HTTPException(401, "invalid API key")
    user = session.get(User, row.user_id)
    if user is None or not user.active or user.org_id != row.org_id:
        raise HTTPException(401, "invalid API key")
    if request.method != "GET":
        raise HTTPException(403, "API keys are read-only")
    now = datetime.now(timezone.utc)
    last = row.last_used_at.replace(tzinfo=timezone.utc) if row.last_used_at and row.last_used_at.tzinfo is None else row.last_used_at
    if last is None or now - last > timedelta(minutes=5):
        row.last_used_at = now
        session.commit()
    return user


def current_user(request: Request, session: Session = Depends(db.get_session)) -> User:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return _api_key_user(request, session, header)
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(401, "not signed in")
    row = session.scalars(select(SessionToken).where(SessionToken.token_hash == _token_hash(token))).first()
    if row is None:
        raise HTTPException(401, "not signed in")
    expires = row.expires_at if row.expires_at.tzinfo else row.expires_at.replace(tzinfo=timezone.utc)
    if expires < datetime.now(timezone.utc) or not row.user.active:
        raise HTTPException(401, "session expired")
    return row.user


# Roles: "member" sees its organisation's portfolio; "admin" also manages its organisation's users;
# "owner" runs the platform and manages users and organisations for every client.
ROLES = ("member", "admin", "owner")


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role not in ("admin", "owner"):
        raise HTTPException(403, "admin only")
    return user


def user_out(user: User) -> dict:
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role,
            "organization": user.org.name, "active": user.active}


def temporary_password() -> str:
    return secrets.token_urlsafe(12)


def set_password(session: Session, user: User, password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    user.password_hash = hash_password(password)
    session.commit()


def end_all_sessions(session: Session, user: User) -> None:
    for row in session.scalars(select(SessionToken).where(SessionToken.user_id == user.id)):
        session.delete(row)
    session.commit()


def create_user(session: Session, org_name: str, email: str, password: str, role: str = "member",
                name: str | None = None) -> User:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    email = email.strip().lower()
    if "@" not in email:
        raise ValueError("not a valid email")
    if session.scalars(select(User).where(User.email == email)).first():
        raise ValueError("a user with this email already exists")
    org = session.scalars(select(Organization).where(Organization.name == org_name)).first()
    if org is None:
        org = Organization(name=org_name)
        session.add(org)
        session.flush()
    user = User(org_id=org.id, email=email, name=name, password_hash=hash_password(password), role=role)
    session.add(user)
    session.commit()
    return user


def bootstrap_admin(session: Session) -> None:
    """Create the platform owner from ADMIN_EMAIL / ADMIN_PASSWORD / ADMIN_ORG if no users exist yet."""
    email, password = os.getenv("ADMIN_EMAIL"), os.getenv("ADMIN_PASSWORD")
    if not email:
        return
    existing = session.scalars(select(User).where(User.email == email.strip().lower())).first()
    if existing is not None:
        # The bootstrap account is the platform owner (older deployments created it as "admin").
        if existing.role != "owner":
            existing.role = "owner"
            session.commit()
        return
    if password and not session.scalars(select(User)).first():
        create_user(session, os.getenv("ADMIN_ORG", "ProjectScore"), email, password, role="owner")
