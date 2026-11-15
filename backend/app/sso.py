"""Single sign-on with Google and Microsoft (OpenID Connect, authorisation code flow with PKCE).

SSO only signs in people who already have a ProjectScore account with the same email address; it never
creates accounts. Setup (in Render's Environment settings):

  APP_URL                     https://projectscore.onrender.com (redirect URIs are built from it)
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
      Redirect URI: {APP_URL}/api/auth/sso/google/callback
  MICROSOFT_CLIENT_ID / MICROSOFT_CLIENT_SECRET / MICROSOFT_ALLOWED_TENANTS
      Redirect URI: {APP_URL}/api/auth/sso/microsoft/callback
      MICROSOFT_ALLOWED_TENANTS is a comma-separated list of the Entra tenant IDs of client companies.
      Microsoft does not guarantee that the email claim was verified, so only listed tenants are trusted.

The ID token is read from the token endpoint over TLS (OIDC Core 3.1.3.7), and its issuer, audience,
expiry and nonce are checked.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth, db
from .models import User

router = APIRouter(prefix="/api")
STATE_COOKIE = "ps_sso"
STATE_TTL = 600

PROVIDERS = {
    "google": {
        "label": "Google",
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "issuers": {"https://accounts.google.com", "accounts.google.com"},
    },
    "microsoft": {
        "label": "Microsoft",
        "authorize": "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
        "token": "https://login.microsoftonline.com/organizations/oauth2/v2.0/token",
        "issuers": None,  # per tenant: https://login.microsoftonline.com/{tid}/v2.0
    },
}


def _env(provider: str, name: str) -> str | None:
    return os.environ.get(f"{provider.upper()}_{name}") or None


def configured(provider: str) -> bool:
    ok = bool(_env(provider, "CLIENT_ID") and _env(provider, "CLIENT_SECRET"))
    if provider == "microsoft":
        ok = ok and bool(allowed_tenants())
    return ok


def allowed_tenants() -> set[str]:
    return {t.strip().lower() for t in (os.environ.get("MICROSOFT_ALLOWED_TENANTS") or "").split(",") if t.strip()}


def redirect_uri(provider: str) -> str:
    base = os.environ.get("APP_URL", "https://projectscore.onrender.com").rstrip("/")
    return f"{base}/api/auth/sso/{provider}/callback"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _mac(body: str) -> str:
    return hmac.new(auth.secret_key().encode(), body.encode(), hashlib.sha256).hexdigest()


def _sign(payload: dict) -> str:
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    return f"{body}.{_mac(body)}"


def _unsign(value: str) -> dict | None:
    try:
        body, mac = value.rsplit(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(mac, _mac(body)):
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except ValueError:
        return None
    return payload if payload.get("exp", 0) > time.time() else None


def decode_claims(id_token: str) -> dict:
    try:
        part = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (IndexError, ValueError) as exc:
        raise ValueError("malformed ID token") from exc


def validate_claims(provider: str, claims: dict, nonce: str) -> str:
    """Returns the verified email address, or raises ValueError."""
    if claims.get("aud") != _env(provider, "CLIENT_ID"):
        raise ValueError("token is for another application")
    if claims.get("nonce") != nonce:
        raise ValueError("nonce mismatch")
    if claims.get("exp", 0) < time.time() - 60:
        raise ValueError("token expired")
    if provider == "google":
        if claims.get("iss") not in PROVIDERS["google"]["issuers"]:
            raise ValueError("wrong issuer")
        if claims.get("email_verified") is not True:
            raise ValueError("email not verified by Google")
        email = claims.get("email")
    else:
        tid = (claims.get("tid") or "").lower()
        if tid not in allowed_tenants():
            raise ValueError("this Microsoft organisation is not enabled for sign-in")
        if claims.get("iss") != f"https://login.microsoftonline.com/{tid}/v2.0":
            raise ValueError("wrong issuer")
        email = claims.get("email") or claims.get("preferred_username")
    if not email or "@" not in email:
        raise ValueError("no email address in token")
    return email.strip().lower()


@router.get("/auth/sso/providers")
def providers() -> list[dict]:
    return [{"id": p, "label": v["label"]} for p, v in PROVIDERS.items() if configured(p)]


@router.get("/auth/sso/{provider}/start")
def start(provider: str) -> RedirectResponse:
    if provider not in PROVIDERS or not configured(provider):
        raise HTTPException(404, "sign-in method not available")
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    params = {"client_id": _env(provider, "CLIENT_ID"), "response_type": "code", "scope": "openid email profile",
              "redirect_uri": redirect_uri(provider), "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account"}
    resp = RedirectResponse(f"{PROVIDERS[provider]['authorize']}?{urlencode(params)}", status_code=302)
    resp.set_cookie(STATE_COOKIE, _sign({"p": provider, "s": state, "n": nonce, "v": verifier,
                                         "exp": time.time() + STATE_TTL}),
                    max_age=STATE_TTL, httponly=True, secure=auth.COOKIE_SECURE, samesite="lax", path="/api/auth/sso")
    return resp


def _fail(message: str) -> RedirectResponse:
    resp = RedirectResponse(f"/?sso_error={message}", status_code=302)
    resp.delete_cookie(STATE_COOKIE, path="/api/auth/sso")
    return resp


def exchange_code(provider: str, code: str, verifier: str) -> dict:
    resp = httpx.post(PROVIDERS[provider]["token"], timeout=15.0, data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(provider),
        "client_id": _env(provider, "CLIENT_ID"), "client_secret": _env(provider, "CLIENT_SECRET"),
        "code_verifier": verifier})
    resp.raise_for_status()
    return resp.json()


@router.get("/auth/sso/{provider}/callback")
def callback(provider: str, request: Request, session: Session = Depends(db.get_session)) -> RedirectResponse:
    st = _unsign(request.cookies.get(STATE_COOKIE, ""))
    if provider not in PROVIDERS or not configured(provider) or not st or st.get("p") != provider:
        return _fail("expired")
    if request.query_params.get("error") or not request.query_params.get("code"):
        return _fail("cancelled")
    if not secrets.compare_digest(request.query_params.get("state", ""), st["s"]):
        return _fail("expired")
    try:
        tokens = exchange_code(provider, request.query_params["code"], st["v"])
        email = validate_claims(provider, decode_claims(tokens.get("id_token", "")), st["n"])
    except (httpx.HTTPError, ValueError):
        return _fail("failed")
    user = session.scalars(select(User).where(func.lower(User.email) == email)).first()
    if user is None or not user.active:
        return _fail("no_account")
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(STATE_COOKIE, path="/api/auth/sso")
    auth.start_session(session, user, resp)
    return resp
