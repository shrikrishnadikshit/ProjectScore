"""Slack and Jira for an organisation.

- Slack: an incoming-webhook URL. Every new alert for the organisation is posted to the channel.
- Jira Cloud: site URL, account email, API token and project key. Any finding type in a fix plan can be sent
  to Jira as an issue in one click.
Only official hosts are accepted (hooks.slack.com and *.atlassian.net), so the feature cannot be pointed at
internal addresses. The webhook URL and API token are never returned by the API after they are saved.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Alert, Finding, OrgIntegration, User

logger = logging.getLogger("projectscore.integrations")
router = APIRouter(prefix="/api")

SLACK_RE = re.compile(r"^https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,200}$")
JIRA_RE = re.compile(r"^https://[a-z0-9][a-z0-9-]{0,62}\.atlassian\.net/?$", re.I)
PROJECT_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,19}$")
SEV_EMOJI = {"critical": ":red_circle:", "warning": ":large_orange_circle:"}


def enabled() -> bool:
    return os.environ.get("INTEGRATIONS", "on").lower() != "off"


def app_url() -> str:
    return os.environ.get("APP_URL", "https://projectscore.onrender.com").rstrip("/")


def _get(session: Session, org_id: int, kind: str) -> OrgIntegration | None:
    return session.scalars(select(OrgIntegration).where(OrgIntegration.org_id == org_id, OrgIntegration.kind == kind)).first()


# ---------- Slack ----------

def slack_post(url: str, text: str, poster=None) -> None:
    (poster or httpx.post)(url, json={"text": text}, timeout=10.0).raise_for_status()


def notify_org(session: Session, org_id: int, title: str, detail: str = "", link: str | None = None, poster=None) -> bool:
    if not (enabled() or poster):
        return False
    row = _get(session, org_id, "slack")
    if not row or not row.enabled or not row.secret:
        return False
    text = f"*{title}*" + (f"\n{detail[:1500]}" if detail else "") + (f"\n<{app_url()}{link}|Open in ProjectScore>" if link else "")
    try:
        slack_post(row.secret, text, poster)
        row.last_error = None
        return True
    except httpx.HTTPError as exc:
        # Never keep the exception text: it contains the webhook URL, which is the secret.
        row.last_error = (f"Slack: HTTP {exc.response.status_code}" if isinstance(exc, httpx.HTTPStatusError)
                          else "Slack: could not connect")
        logger.warning("slack post failed for org %s: %s", org_id, type(exc).__name__)
        return False
    finally:
        session.commit()


def _dispatch(alert_ids: list[int]) -> None:
    session = db.SessionLocal()
    try:
        for a in session.scalars(select(Alert).where(Alert.id.in_(alert_ids))).all():
            emoji = SEV_EMOJI.get(a.severity, "")
            notify_org(session, a.org_id, f"{emoji} {a.title}".strip(), a.detail or "",
                       link=f"/entities/{a.entity_id}" if a.entity_id else "/alerts")
        from .webhooks import dispatch as webhook_dispatch

        webhook_dispatch(session, session.scalars(select(Alert).where(Alert.id.in_(alert_ids))).all())
    except Exception:
        logger.exception("alert dispatch failed")
    finally:
        session.close()


@event.listens_for(Session, "after_flush")
def _collect_alerts(session, flush_context):
    new = [o for o in session.new if isinstance(o, Alert)]
    if new:
        session.info.setdefault("new_alerts", []).extend(new)


@event.listens_for(Session, "after_commit")
def _send_alerts(session):
    alerts = session.info.pop("new_alerts", [])
    ids = [a.id for a in alerts if getattr(a, "id", None)]
    if ids and enabled():
        threading.Thread(target=_dispatch, args=(ids,), daemon=True).start()


@event.listens_for(Session, "after_rollback")
def _drop_alerts(session):
    session.info.pop("new_alerts", None)


# ---------- Jira ----------

def _adf(paragraphs: list[str]) -> dict:
    return {"type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": p[:30000]}]} for p in paragraphs if p]}


def jira_issue(row: OrgIntegration, summary: str, paragraphs: list[str], labels: list[str], poster=None) -> dict:
    cfg = row.config or {}
    payload = {"fields": {"project": {"key": cfg["project"]}, "summary": summary[:250],
                          "issuetype": {"name": cfg.get("issue_type") or "Task"},
                          "description": _adf(paragraphs), "labels": labels}}
    url = cfg["site"].rstrip("/") + "/rest/api/3/issue"
    r = (poster or httpx.post)(url, json=payload, auth=(cfg["email"], row.secret), timeout=20.0,
                               headers={"Accept": "application/json"})
    r.raise_for_status()
    key = r.json().get("key")
    return {"key": key, "url": f"{cfg['site'].rstrip('/')}/browse/{key}"}


# ---------- API ----------

def _out(row: OrgIntegration | None, kind: str) -> dict:
    if row is None:
        return {"kind": kind, "connected": False}
    cfg = dict(row.config or {})
    return {"kind": kind, "connected": bool(row.secret), "enabled": row.enabled, "config": cfg,
            "last_error": row.last_error, "updated_at": row.updated_at.isoformat() if row.updated_at else None}


@router.get("/integrations")
def list_integrations(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .webhooks import out as webhook_out

    return {**{k: _out(_get(session, user.org_id, k), k) for k in ("slack", "jira")},
            "webhook": webhook_out(_get(session, user.org_id, "webhook"))}


class SlackIn(BaseModel):
    webhook_url: str | None = None
    enabled: bool = True


class JiraIn(BaseModel):
    site: str
    email: str
    project: str
    issue_type: str = "Task"
    api_token: str | None = None
    enabled: bool = True


def _upsert(session: Session, org_id: int, kind: str) -> OrgIntegration:
    row = _get(session, org_id, kind)
    if row is None:
        row = OrgIntegration(org_id=org_id, kind=kind, config={})
        session.add(row)
    row.updated_at = datetime.now(timezone.utc)
    return row


@router.put("/integrations/slack")
def set_slack(body: SlackIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    row = _upsert(session, user.org_id, "slack")
    if body.webhook_url:
        if not SLACK_RE.match(body.webhook_url.strip()):
            raise HTTPException(422, "use a Slack incoming-webhook URL (https://hooks.slack.com/services/...)")
        row.secret = body.webhook_url.strip()
    if not row.secret:
        raise HTTPException(422, "a webhook URL is needed")
    row.enabled, row.last_error = body.enabled, None
    session.commit()
    return _out(row, "slack")


@router.put("/integrations/jira")
def set_jira(body: JiraIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    site = body.site.strip().rstrip("/")
    if not JIRA_RE.match(site + "/"):
        raise HTTPException(422, "use your Jira Cloud address, like https://yourcompany.atlassian.net")
    project = body.project.strip().upper()
    if not PROJECT_RE.match(project):
        raise HTTPException(422, "the project key looks like SEC or VENDOR")
    if "@" not in body.email:
        raise HTTPException(422, "enter the email of the Jira account that owns the API token")
    row = _upsert(session, user.org_id, "jira")
    row.config = {"site": site, "email": body.email.strip(), "project": project,
                  "issue_type": (body.issue_type or "Task").strip()[:40]}
    if body.api_token:
        row.secret = body.api_token.strip()[:500]
    if not row.secret:
        raise HTTPException(422, "an API token is needed")
    row.enabled, row.last_error = body.enabled, None
    session.commit()
    return _out(row, "jira")


@router.delete("/integrations/{kind}", status_code=204)
def remove(kind: str, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> None:
    row = _get(session, user.org_id, kind)
    if row:
        session.delete(row)
        session.commit()


@router.post("/integrations/slack/test")
def test_slack(user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    ok = notify_org(session, user.org_id, "ProjectScore is connected to this channel",
                    "Alerts about your vendors will appear here.", link="/alerts")
    if not ok:
        row = _get(session, user.org_id, "slack")
        raise HTTPException(502, (row.last_error if row else None) or "Slack is not connected")
    return {"ok": True}


class IssueIn(BaseModel):
    entity_id: int
    code: str


@router.post("/integrations/jira/issue", status_code=201)
def create_issue(body: IssueIn, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item
    from .remediation import guidance

    item = _portfolio_item(session, user, body.entity_id)
    row = _get(session, user.org_id, "jira")
    if not row or not row.enabled or not row.secret:
        raise HTTPException(409, "connect Jira in Settings first")
    fs = session.scalars(select(Finding).where(Finding.entity_id == body.entity_id, Finding.code == body.code,
                                               Finding.status == "open")).all()
    if not fs:
        raise HTTPException(404, "no open findings of this type")
    g = guidance(body.code)
    assets = sorted({f.asset_value for f in fs})
    paragraphs = [f"Vendor: {item.entity.name} ({item.entity.primary_domain})",
                  f"Issue: {fs[0].title} (severity {fs[0].severity})",
                  f"Why it matters: {g['why']}",
                  "How to fix: " + " ".join(f"{i + 1}. {s}" for i, s in enumerate(g["fix"])),
                  "Affected: " + ", ".join(assets[:30]) + (f" and {len(assets) - 30} more" if len(assets) > 30 else ""),
                  f"Details: {app_url()}/entities/{body.entity_id}"]
    try:
        out = jira_issue(row, f"[{item.entity.name}] {fs[0].title}", paragraphs,
                         ["projectscore", re.sub(r"[^a-z0-9_-]", "", body.code.lower())[:50]])
    except httpx.HTTPStatusError as exc:
        row.last_error = f"Jira: HTTP {exc.response.status_code}"
        session.commit()
        raise HTTPException(502, f"Jira refused the issue (HTTP {exc.response.status_code}). Check the project key, issue type and token.")
    except httpx.HTTPError as exc:
        row.last_error = "Jira: could not connect"
        session.commit()
        raise HTTPException(502, "could not reach Jira")
    row.last_error = None
    session.commit()
    return out
