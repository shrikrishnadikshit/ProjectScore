"""Consent-based in-depth web scans with Nuclei (free, MIT-licensed).

Guard rails (BRS 4.1, 4.2 and 4.4):
  1. The organisation proves control of the domain with a DNS TXT record.
  2. A named person gives written authorisation, stored verbatim with who, when and from where.
  3. Only the verified domain and its own subdomains are scanned; denial-of-service, brute-force
     and fuzzing templates are excluded; requests are rate-limited.
  4. Results are shown separately and never change the public security rating.
"""

import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import threading
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .collectors.dns_util import LookupFailed, txt_records
from .collectors.discovery import discover_hosts
from .collectors.netsafe import public_hosts
from .models import ActiveScan, DomainVerification, Entity, User
from .optout import _DOMAIN_RE

logger = logging.getLogger("projectscore.active")
router = APIRouter(prefix="/api")

NUCLEI_BIN = os.getenv("NUCLEI_BIN", "nuclei")
VERIFY_PREFIX = "_projectscore-verify"
VERIFICATION_VALID_DAYS = 90
MAX_TARGETS = 25
SCAN_TIMEOUT_SECONDS = int(os.getenv("ACTIVE_SCAN_TIMEOUT_SECONDS", "2700"))
MIN_HOURS_BETWEEN_SCANS = 24
EXCLUDED_TAGS = "dos,bruteforce,fuzz,fuzzing,intrusive,headless"
AUTHORISATION_TEXT = (
    "I confirm that I am authorised by the organisation that owns {domain} to approve security testing "
    "of {domain} and its subdomains, and I authorise {platform} to perform an automated, rate-limited "
    "vulnerability scan of these systems now. I understand the scan sends requests that test for known "
    "weaknesses and may appear in security logs and monitoring."
)

_scan_lock = threading.Lock()  # one in-depth scan at a time on this server


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def nuclei_available() -> bool:
    return shutil.which(NUCLEI_BIN) is not None


# ---------- Verification ----------

class DomainIn(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        v = v.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0].removeprefix("www.")
        if not _DOMAIN_RE.match(v):
            raise ValueError("not a valid domain")
        return v


def _verification_out(v: DomainVerification) -> dict:
    verified = _aware(v.verified_at)
    valid = bool(verified and verified > _now() - timedelta(days=VERIFICATION_VALID_DAYS))
    return {"id": v.id, "domain": v.domain, "record_name": f"{VERIFY_PREFIX}.{v.domain}",
            "record_value": f"projectscore-verify={v.token}", "verified_at": verified.isoformat() if verified else None,
            "valid": valid}


@router.get("/verifications")
def list_verifications(user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> list[dict]:
    rows = session.scalars(select(DomainVerification).where(DomainVerification.org_id == user.org_id)
                           .order_by(DomainVerification.domain)).all()
    return [_verification_out(v) for v in rows]


@router.post("/verifications", status_code=201)
def start_verification(body: DomainIn, user: User = Depends(auth.require_admin),
                       session: Session = Depends(db.get_session)) -> dict:
    existing = session.scalars(select(DomainVerification).where(
        DomainVerification.org_id == user.org_id, DomainVerification.domain == body.domain)).first()
    if existing:
        return _verification_out(existing)
    v = DomainVerification(org_id=user.org_id, domain=body.domain, token=secrets.token_hex(16), created_by=user.id)
    session.add(v)
    session.commit()
    return _verification_out(v)


def record_matches(records: list[str], token: str) -> bool:
    return any(r.strip().strip('"') == f"projectscore-verify={token}" for r in records)


@router.post("/verifications/{verification_id}/check")
def check_verification(verification_id: int, user: User = Depends(auth.require_admin),
                       session: Session = Depends(db.get_session)) -> dict:
    v = session.get(DomainVerification, verification_id)
    if v is None or v.org_id != user.org_id:
        raise HTTPException(404, "verification not found")
    try:
        records = txt_records(f"{VERIFY_PREFIX}.{v.domain}")
    except LookupFailed:
        raise HTTPException(503, "DNS lookup failed; please try again in a minute")
    if not record_matches(records, v.token):
        raise HTTPException(409, "the DNS record was not found yet. DNS changes can take up to an hour to appear")
    v.verified_at = _now()
    session.commit()
    return _verification_out(v)


# ---------- Scans ----------

class ActiveScanIn(BaseModel):
    domain: str
    authoriser_name: str
    authoriser_title: str
    confirm: bool

    @field_validator("authoriser_name", "authoriser_title")
    @classmethod
    def _required(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 2:
            raise ValueError("required")
        return v[:255]


def _scan_out(s: ActiveScan, with_results: bool = False) -> dict:
    out = {"id": s.id, "domain": s.domain, "status": s.status, "targets": s.targets,
           "authoriser_name": s.authoriser_name, "authoriser_title": s.authoriser_title,
           "created_at": _aware(s.created_at).isoformat(),
           "started_at": _aware(s.started_at).isoformat() if s.started_at else None,
           "finished_at": _aware(s.finished_at).isoformat() if s.finished_at else None,
           "finding_count": len(s.results or []), "error": s.error}
    if with_results:
        out["results"] = s.results or []
        out["authorisation_text"] = s.authorisation_text
    return out


@router.get("/active-scans/config")
def active_config(user: User = Depends(auth.require_admin)) -> dict:
    return {"available": nuclei_available(),
            "authorisation_text": AUTHORISATION_TEXT.format(domain="{domain}", platform="ProjectScore")}


@router.get("/active-scans")
def list_active_scans(user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> list[dict]:
    rows = session.scalars(select(ActiveScan).where(ActiveScan.org_id == user.org_id)
                           .order_by(ActiveScan.created_at.desc())).all()
    return [_scan_out(s) for s in rows]


@router.get("/active-scans/{scan_id}")
def get_active_scan(scan_id: int, user: User = Depends(auth.require_admin),
                    session: Session = Depends(db.get_session)) -> dict:
    s = session.get(ActiveScan, scan_id)
    if s is None or s.org_id != user.org_id:
        raise HTTPException(404, "scan not found")
    return _scan_out(s, with_results=True)


def scan_targets(session: Session, domain: str, discover=None) -> list[str]:
    """The verified domain, www, and its own subdomains (known assets plus fresh discovery)."""
    hosts = [domain, f"www.{domain}"]
    entity = session.scalars(select(Entity).where(Entity.primary_domain == domain)).first()
    if entity:
        hosts += [a.value for a in entity.assets if a.type == "subdomain"]
    try:
        hosts += (discover or discover_hosts)(domain)
    except Exception:  # discovery is best-effort here
        logger.warning("discovery failed for in-depth scan of %s", domain)
    in_scope = [h for h in dict.fromkeys(hosts) if h == domain or h.endswith("." + domain)]
    in_scope = public_hosts(in_scope)  # never point Nuclei at private or internal addresses
    return [f"https://{h}" for h in in_scope[:MAX_TARGETS]]


@router.post("/active-scans", status_code=202)
def request_active_scan(body: ActiveScanIn, request: Request, user: User = Depends(auth.require_admin),
                        session: Session = Depends(db.get_session)) -> dict:
    domain = DomainIn(domain=body.domain).domain
    if not body.confirm:
        raise HTTPException(422, "the authorisation must be confirmed")
    v = session.scalars(select(DomainVerification).where(
        DomainVerification.org_id == user.org_id, DomainVerification.domain == domain)).first()
    if v is None or not _verification_out(v)["valid"]:
        raise HTTPException(403, "verify ownership of this domain first (DNS record), then try again")
    from .optout import is_opted_out
    if is_opted_out(session, domain):
        raise HTTPException(409, "this domain has opted out of scanning")
    recent = session.scalars(select(ActiveScan).where(
        ActiveScan.org_id == user.org_id, ActiveScan.domain == domain,
        ActiveScan.status.in_(("queued", "running", "done")))
        .order_by(ActiveScan.created_at.desc())).first()
    if recent and _aware(recent.created_at) > _now() - timedelta(hours=MIN_HOURS_BETWEEN_SCANS):
        raise HTTPException(429, "an in-depth scan of this domain ran in the last 24 hours")
    if not nuclei_available():
        raise HTTPException(503, "the scanner is not installed on this server")
    client = request.headers.get("x-forwarded-for", request.client.host if request.client else "")
    scan = ActiveScan(org_id=user.org_id, domain=domain, requested_by=user.id,
                      authoriser_name=body.authoriser_name, authoriser_title=body.authoriser_title,
                      authorisation_text=AUTHORISATION_TEXT.format(domain=domain, platform="ProjectScore"),
                      authorised_from_ip=client.split(",")[0].strip()[:64])
    session.add(scan)
    session.commit()
    threading.Thread(target=run_scan, args=(scan.id,), daemon=True, name=f"active-scan-{scan.id}").start()
    return _scan_out(scan)


# ---------- Runner ----------

def parse_results(lines) -> list[dict]:
    results = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        info = d.get("info") or {}
        cls = info.get("classification") or {}
        results.append({
            "template": d.get("template-id"), "name": info.get("name"), "severity": info.get("severity", "unknown"),
            "description": (info.get("description") or "").strip()[:1000],
            "matched_at": d.get("matched-at") or d.get("host"),
            "cves": [c.upper() for c in (cls.get("cve-id") or [])],
            "references": (info.get("reference") or [])[:5] if isinstance(info.get("reference"), list) else [],
            "remediation": (info.get("remediation") or "").strip()[:1000],
        })
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(results, key=lambda r: (order.get(r["severity"], 5), r["matched_at"] or ""))


def nuclei_command(targets_file: str, output_file: str) -> list[str]:
    from .collectors.web import USER_AGENT

    extra = ["-t", os.environ["NUCLEI_TEMPLATES"]] if os.getenv("NUCLEI_TEMPLATES") else []
    return [NUCLEI_BIN, "-l", targets_file, *extra, "-jsonl", "-o", output_file, "-silent", "-nc", "-duc", "-or", "-ot",
            "-severity", "low,medium,high,critical", "-exclude-tags", EXCLUDED_TAGS,
            "-rate-limit", "20", "-concurrency", "10", "-timeout", "10", "-retries", "1",
            "-H", f"User-Agent: {USER_AGENT} in-depth authorised scan"]


def run_scan(scan_id: int, discover=None, runner=subprocess.run) -> None:
    with _scan_lock:
        session = db.SessionLocal()
        try:
            scan = session.get(ActiveScan, scan_id)
            scan.status, scan.started_at = "running", _now()
            scan.targets = scan_targets(session, scan.domain, discover)
            session.commit()
            with tempfile.TemporaryDirectory() as tmp:
                targets_file, output_file = os.path.join(tmp, "targets.txt"), os.path.join(tmp, "out.jsonl")
                with open(targets_file, "w") as fh:
                    fh.write("\n".join(scan.targets))
                proc = runner(nuclei_command(targets_file, output_file), capture_output=True, text=True,
                              timeout=SCAN_TIMEOUT_SECONDS)
                lines = open(output_file).readlines() if os.path.exists(output_file) else []
            scan.results = parse_results(lines)
            if proc.returncode != 0 and not lines:
                detail = re.sub(r"\x1b\[[0-9;]*m", "", proc.stderr or "").strip()
                if "no templates" in detail.lower():
                    detail = "the scanner's check templates are not installed yet; please try again in a few minutes"
                scan.status, scan.error = "failed", (detail or "scanner exited with an error")[-2000:]
            else:
                scan.status = "done"
        except subprocess.TimeoutExpired:
            scan.status, scan.error = "failed", "the scan took too long and was stopped"
        except Exception as exc:
            logger.exception("in-depth scan %s failed", scan_id)
            scan.status, scan.error = "failed", str(exc)[:2000]
        finally:
            scan.finished_at = _now()
            session.commit()
            session.close()


def update_templates_async() -> None:
    """Refresh Nuclei's free community templates in the background (best effort)."""
    if not nuclei_available() or os.getenv("NUCLEI_AUTO_UPDATE", "true").lower() == "false":
        return

    def _update():
        try:
            subprocess.run([NUCLEI_BIN, "-update-templates", "-duc", "-silent"], capture_output=True, timeout=600)
        except Exception:
            logger.warning("nuclei template update failed", exc_info=True)

    threading.Thread(target=_update, daemon=True, name="nuclei-templates").start()


def fail_interrupted_scans(session: Session) -> None:
    """Scans left running when the server restarted can't resume; mark them failed."""
    for s in session.scalars(select(ActiveScan).where(ActiveScan.status.in_(("queued", "running")))):
        s.status, s.error, s.finished_at = "failed", "the server restarted during the scan; please run it again", _now()
    session.commit()
