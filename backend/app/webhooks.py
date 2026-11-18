"""Signed webhooks (BRS INT-003).

An organisation can give one HTTPS address. Every new alert is POSTed there as JSON. Each request carries

    X-ProjectScore-Signature: t=<unix time>,v1=<hex HMAC-SHA256 of "<t>.<raw body>" with the signing secret>

so the receiver can check it came from us and is fresh (reject anything older than 5 minutes). The signing
secret is made by us, shown once, and never returned again. Only public addresses are called: the host is
resolved before every send and private, loopback and link-local addresses are refused, and redirects are not
followed, so the feature cannot be used to reach internal systems.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import auth, db
from .integrations import _get, _upsert, enabled
from .models import Alert, User

logger = logging.getLogger("projectscore.webhooks")
router = APIRouter(prefix="/api")
HEADER = "X-ProjectScore-Signature"


def sign(secret: str, body: bytes, ts: int | None = None) -> str:
    ts = int(time.time()) if ts is None else ts
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def check_signature(secret: str, body: bytes, header: str, tolerance: int = 300, now: float | None = None) -> bool:
    """What a receiver does; also used in tests and shown in the docs."""
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts = int(parts["t"])
    except (ValueError, KeyError):
        return False
    if abs((now or time.time()) - ts) > tolerance:
        return False
    return hmac.compare_digest(sign(secret, body, ts), f"t={ts},v1={parts.get('v1', '')}")


def _public(url: str, resolver=socket.getaddrinfo) -> bool:
    u = urlparse(url)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        return False
    try:
        addrs = {a[4][0] for a in resolver(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)}
    except (socket.gaierror, UnicodeError):
        return False
    return bool(addrs) and all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addrs)


def payload(a: Alert) -> dict:
    return {"id": str(uuid.uuid4()), "type": f"alert.{a.kind}", "created_at": datetime.now(timezone.utc).isoformat(),
            "data": {"alert_id": a.id, "entity_id": a.entity_id, "severity": a.severity, "title": a.title,
                     "detail": a.detail}}


def send(session: Session, org_id: int, event: dict, poster=None, resolver=socket.getaddrinfo) -> bool:
    row = _get(session, org_id, "webhook")
    if not row or not row.enabled or not row.secret:
        return False
    url = (row.config or {}).get("url", "")
    body = json.dumps(event, separators=(",", ":")).encode()
    try:
        if not _public(url, resolver):
            raise ValueError("address is not public")
        r = (poster or httpx.post)(url, content=body, timeout=10.0, follow_redirects=False,
                                   headers={"Content-Type": "application/json", HEADER: sign(row.secret, body),
                                            "User-Agent": "ProjectScore-Webhook/1"})
        r.raise_for_status()
        row.last_error = None
        return True
    except ValueError:
        row.last_error = "Webhook: the address does not resolve to a public internet address"
    except httpx.HTTPStatusError as exc:
        row.last_error = f"Webhook: HTTP {exc.response.status_code}"
    except httpx.HTTPError:
        row.last_error = "Webhook: could not connect"
    finally:
        session.commit()
    logger.warning("webhook failed for org %s", org_id)
    return False


def out(row) -> dict:
    if row is None:
        return {"kind": "webhook", "connected": False}
    return {"kind": "webhook", "connected": bool(row.secret), "enabled": row.enabled, "config": dict(row.config or {}),
            "last_error": row.last_error, "updated_at": row.updated_at.isoformat() if row.updated_at else None}


class WebhookIn(BaseModel):
    url: str
    enabled: bool = True
    new_secret: bool = False


@router.put("/integrations/webhook")
def set_webhook(body: WebhookIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    url = body.url.strip()
    if len(url) > 500 or not _public(url):
        raise HTTPException(422, "use an https:// address on the public internet")
    row = _upsert(session, user.org_id, "webhook")
    row.config = {"url": url}
    fresh = None
    if body.new_secret or not row.secret:
        fresh = row.secret = "whsec_" + secrets.token_urlsafe(32)
    row.enabled, row.last_error = body.enabled, None
    session.commit()
    return {**out(row), "signing_secret": fresh}


@router.post("/integrations/webhook/test")
def test_webhook(user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    event = {"id": str(uuid.uuid4()), "type": "ping", "created_at": datetime.now(timezone.utc).isoformat(),
             "data": {"message": "ProjectScore webhook test"}}
    if not send(session, user.org_id, event):
        row = _get(session, user.org_id, "webhook")
        raise HTTPException(502, (row.last_error if row else None) or "no webhook is set up")
    return {"ok": True}


def dispatch(session: Session, alerts: list[Alert]) -> None:
    if not enabled():
        return
    for a in alerts:
        send(session, a.org_id, payload(a))
