"""Source code reviews with free, open-source scanners.

- Gitleaks (MIT): hard-coded passwords, API keys and tokens. Secrets are redacted before storing.
- OSV-Scanner (Apache 2.0, Google): third-party libraries with known vulnerabilities, from lock files
  and manifests in most ecosystems (npm, PyPI, Maven, Go, Cargo, NuGet, Composer, RubyGems...).
- Bandit (Apache 2.0, PyCQA): insecure patterns in Python code.

Admins upload a zip or give a public Git link (GitHub, GitLab or Bitbucket). The code is never run:
the tools only read it. It is deleted as soon as the scan finishes, and only the findings are kept.
Reviews run one at a time in the background.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import shutil
import subprocess
import tempfile
import threading
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import auth, db
from .collectors.netsafe import is_public_host
from .models import CodeReview, User

logger = logging.getLogger("projectscore.codereview")
router = APIRouter(prefix="/api")

MAX_UPLOAD = 50 * 1024 * 1024
MAX_EXTRACTED = 300 * 1024 * 1024
MAX_FILES = 30000
DAILY_LIMIT = 10
TIMEOUT = 600
GIT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}
SEVERITIES = ["critical", "high", "medium", "low", "info"]
WORK_DIR = Path(os.environ.get("CODE_REVIEW_DIR", tempfile.gettempdir())) / "projectscore-code"

_queue: "queue.Queue[int]" = queue.Queue()
_worker_started = threading.Lock()
_worker: threading.Thread | None = None


# ---------- safe input handling ----------

def validate_git_url(url: str) -> str:
    url = url.strip()
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.username or parts.password or parts.port:
        raise ValueError("use an https link without a username, password or port")
    host = (parts.hostname or "").lower()
    if host not in GIT_HOSTS:
        raise ValueError("only public GitHub, GitLab and Bitbucket links are supported")
    if not re.fullmatch(r"/[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-/]+?(\.git)?/?", parts.path or ""):
        raise ValueError("this does not look like a repository link")
    return f"https://{host}{parts.path.rstrip('/')}"


def safe_extract(zip_path: Path, dest: Path) -> None:
    """Extract a zip, refusing path traversal, links, zip bombs and huge file counts."""
    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError("the archive has too many files")
        if sum(i.file_size for i in infos) > MAX_EXTRACTED:
            raise ValueError("the archive is too large when extracted (limit 300 MB)")
        root = dest.resolve()
        for info in infos:
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                continue  # symbolic link: skip
            target = (dest / info.filename).resolve()
            if root not in target.parents and target != root:
                raise ValueError("the archive contains unsafe paths")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, 1024 * 1024)


def clone(url: str, dest: Path, runner=subprocess.run) -> None:
    host = urlsplit(url).hostname or ""
    if not is_public_host(host):
        raise ValueError("the repository host could not be reached")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_TERMINAL_PROMPT": "0", "HOME": str(dest.parent),
           "GIT_CONFIG_NOSYSTEM": "1"}
    result = runner(["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
                     "-c", "core.symlinks=false", "clone", "--depth", "1", "--single-branch", "--no-tags",
                     "--quiet", url, str(dest)], capture_output=True, text=True, timeout=180, env=env)
    if result.returncode != 0:
        raise ValueError("the repository could not be cloned; check that the link is right and the repository is public")
    total = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file() and not f.is_symlink())
    if total > MAX_EXTRACTED:
        raise ValueError("the repository is too large (limit 300 MB)")


# ---------- tool output parsing ----------

def _rel(path: str, root: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        return path.split(str(root))[-1].lstrip("/")


def parse_gitleaks(data: list, root: Path) -> list[dict]:
    out = []
    for leak in data or []:
        out.append({"tool": "Gitleaks", "rule": leak.get("RuleID", "secret"), "severity": "high",
                    "title": f"Possible hard-coded secret: {leak.get('Description') or leak.get('RuleID')}",
                    "file": _rel(leak.get("File", ""), root), "line": leak.get("StartLine"),
                    "detail": "Secret value redacted.",
                    "fix": "Revoke and rotate this secret now, remove it from the code (and Git history), "
                           "and load it from environment variables or a secrets manager instead."})
    return out


def _cvss_severity(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


def _fixed_versions(vuln: dict) -> list[str]:
    fixed = []
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            fixed += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted(set(fixed), key=_vkey)


def _vkey(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else -1 for x in re.split(r"[.\-+]", str(v).lstrip("v")))


def _best_fix(current: str, fixed: list[str]) -> str | None:
    """The lowest fixed version above the one in use (stays on the same release line where possible)."""
    fixed = sorted(fixed, key=_vkey)
    above = [f for f in fixed if _vkey(f) > _vkey(current)]
    return (above or fixed or [None])[0]


def parse_osv(data: dict, root: Path) -> list[dict]:
    out = []
    for res in (data or {}).get("results", []) or []:
        source = _rel((res.get("source") or {}).get("path", ""), root)
        for pkg in res.get("packages", []) or []:
            p = pkg.get("package", {})
            vulns = {v["id"]: v for v in pkg.get("vulnerabilities", []) or [] if v.get("id")}
            for group in pkg.get("groups", []) or [{"ids": [i]} for i in vulns]:
                ids = group.get("ids") or []
                primary = vulns.get(ids[0], {}) if ids else {}
                aliases = sorted({a for i in ids for a in (vulns.get(i, {}).get("aliases") or []) + [i]})
                cves = [a for a in aliases if a.startswith("CVE-")]
                name, version = p.get("name", "?"), p.get("version", "?")
                fix_to = _best_fix(version, _fixed_versions(primary))
                out.append({"tool": "OSV-Scanner", "rule": ids[0] if ids else "vulnerability",
                            "severity": _cvss_severity(group.get("max_severity")),
                            "title": f"{name} {version}: {primary.get('summary') or 'known vulnerability'}"[:300],
                            "file": source, "line": None, "cves": cves[:10],
                            "detail": f"{p.get('ecosystem', '')} package; advisories: {', '.join(aliases[:6])}",
                            "fix": (f"Upgrade {name} to {fix_to} or later." if fix_to
                                    else f"No fixed version published yet; consider replacing {name} or reducing its exposure.")})
    return out


def parse_bandit(data: dict, root: Path) -> list[dict]:
    out = []
    for r in (data or {}).get("results", []) or []:
        sev = (r.get("issue_severity") or "LOW").lower()
        if sev == "low" and (r.get("issue_confidence") or "").upper() == "LOW":
            continue  # low severity and low confidence: mostly noise
        cwe = (r.get("issue_cwe") or {}).get("id")
        out.append({"tool": "Bandit", "rule": f"{r.get('test_id')} {r.get('test_name')}", "severity": sev,
                    "title": r.get("issue_text", "")[:300], "file": _rel(r.get("filename", ""), root),
                    "line": r.get("line_number"), "detail": f"Confidence: {(r.get('issue_confidence') or '').lower()}"
                    + (f"; CWE-{cwe}" if cwe else ""),
                    "fix": f"See {r.get('more_info')}" if r.get("more_info") else "Review and rewrite this code safely."})
    return out


# ---------- running the tools ----------

def run_tools(root: Path, runner=subprocess.run) -> tuple[list[dict], list[str]]:
    findings, notes = [], []
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": str(root.parent)}

    def tool(name, cmd, parse, out_file=None, ok=(0,)):
        try:
            res = runner(cmd, capture_output=True, text=True, timeout=TIMEOUT, env=env, cwd=str(root.parent))
        except FileNotFoundError:
            notes.append(f"{name} is not installed on this server")
            return
        except subprocess.TimeoutExpired:
            notes.append(f"{name} timed out")
            return
        raw = Path(out_file).read_text() if out_file and Path(out_file).exists() else res.stdout
        if res.returncode not in ok and not raw.strip():
            notes.append(f"{name} failed: {(res.stderr or '').strip()[:200]}")
            return
        try:
            findings.extend(parse(json.loads(raw or "null"), root))
        except (ValueError, TypeError, KeyError) as exc:
            notes.append(f"{name} output could not be read: {exc}")

    report = root.parent / "gitleaks.json"
    tool("Gitleaks", ["gitleaks", "dir", str(root), "--report-format", "json", "--report-path", str(report),
                      "--redact", "--no-banner", "--exit-code", "0", "--log-level", "error"], parse_gitleaks, report)
    tool("OSV-Scanner", ["osv-scanner", "scan", "source", "--recursive", "--format", "json", str(root)],
         parse_osv, ok=(0, 1, 128))
    tool("Bandit", ["bandit", "-r", str(root), "-f", "json", "-q", "--exit-zero",
                    "-x", ",".join(str(root / d) for d in ("node_modules", ".venv", "venv", "tests", "test"))],
         parse_bandit)
    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]) if f["severity"] in SEVERITIES else 9, f["tool"], f["file"]))
    return findings, notes


def summarise(findings: list[dict], notes: list[str]) -> dict:
    return {"total": len(findings), "by_severity": {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES},
            "by_tool": {t: sum(f["tool"] == t for f in findings) for t in ("Gitleaks", "OSV-Scanner", "Bandit")},
            "notes": notes}


def process(review_id: int, runner=subprocess.run) -> None:
    session = db.SessionLocal()
    work = WORK_DIR / str(review_id)
    try:
        review = session.get(CodeReview, review_id)
        if review is None or review.status != "queued":
            return
        review.status = "running"
        session.commit()
        code = work / "code"
        try:
            if review.source_type == "git":
                clone(review.source, code, runner=runner)
            else:
                code.mkdir(parents=True, exist_ok=True)
                safe_extract(work / "upload.zip", code)
            findings, notes = run_tools(code, runner=runner)
            review.results, review.summary, review.status = findings[:2000], summarise(findings, notes), "done"
        except (ValueError, zipfile.BadZipFile, OSError, subprocess.TimeoutExpired) as exc:
            review.status, review.error = "failed", str(exc)[:1000]
        review.finished_at = datetime.now(timezone.utc)
        session.commit()
    except Exception:
        logger.exception("code review %s failed", review_id)
        session.rollback()
        review = session.get(CodeReview, review_id)
        if review:
            review.status, review.error = "failed", "the review failed unexpectedly"
            session.commit()
    finally:
        session.close()
        shutil.rmtree(work, ignore_errors=True)  # never keep customer code


def _work() -> None:
    while True:
        review_id = _queue.get()
        try:
            process(review_id)
        finally:
            _queue.task_done()


def enqueue(review_id: int) -> None:
    global _worker
    with _worker_started:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_work, daemon=True, name="code-review")
            _worker.start()
    _queue.put(review_id)


def fail_interrupted(session: Session) -> None:
    for r in session.scalars(select(CodeReview).where(CodeReview.status.in_(("queued", "running")))).all():
        r.status, r.error = "failed", "the server restarted before this review finished; please start it again"
    session.commit()


# ---------- API ----------

def _out(r: CodeReview, detail: bool = False) -> dict:
    out = {"id": r.id, "name": r.name, "source_type": r.source_type, "source": r.source, "status": r.status,
           "error": r.error, "summary": r.summary or {}, "created_at": r.created_at.isoformat(),
           "finished_at": r.finished_at.isoformat() if r.finished_at else None}
    if detail:
        out["results"] = r.results or []
    return out


def _check_quota(session: Session, user: User) -> None:
    since = datetime.now(timezone.utc) - timedelta(days=1)
    n = session.scalar(select(func.count()).select_from(CodeReview).where(
        CodeReview.org_id == user.org_id, CodeReview.created_at >= since))
    if (n or 0) >= DAILY_LIMIT:
        raise HTTPException(429, f"your organisation has started {DAILY_LIMIT} code reviews today; try again tomorrow")


class GitIn(BaseModel):
    url: str
    confirm: bool = False

    @field_validator("url")
    @classmethod
    def _url(cls, v):
        return validate_git_url(v)


@router.post("/code-reviews/git", status_code=202)
def start_git(body: GitIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    if not body.confirm:
        raise HTTPException(422, "please confirm you are authorised to have this code reviewed")
    _check_quota(session, user)
    name = "/".join(urlsplit(body.url).path.strip("/").split("/")[:2]).removesuffix(".git")
    r = CodeReview(org_id=user.org_id, requested_by=user.id, name=name[:200], source_type="git", source=body.url)
    session.add(r)
    session.commit()
    enqueue(r.id)
    return _out(r)


@router.post("/code-reviews/upload", status_code=202)
async def start_upload(file: UploadFile = File(...), confirm: bool = Form(False), user: User = Depends(auth.require_admin),
                       session: Session = Depends(db.get_session)) -> dict:
    if not confirm:
        raise HTTPException(422, "please confirm you are authorised to have this code reviewed")
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(422, "upload a .zip file")
    _check_quota(session, user)
    r = CodeReview(org_id=user.org_id, requested_by=user.id, name=Path(file.filename).name[:200], source_type="zip",
                   source=Path(file.filename).name[:500])
    session.add(r)
    session.commit()
    work = WORK_DIR / str(r.id)
    work.mkdir(parents=True, exist_ok=True)
    size = 0
    with open(work / "upload.zip", "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD:
                out.close()
                shutil.rmtree(work, ignore_errors=True)
                r.status, r.error = "failed", "the file is larger than 50 MB"
                session.commit()
                raise HTTPException(413, "the file is larger than 50 MB")
            out.write(chunk)
    if not zipfile.is_zipfile(work / "upload.zip"):
        shutil.rmtree(work, ignore_errors=True)
        r.status, r.error = "failed", "this is not a valid zip file"
        session.commit()
        raise HTTPException(422, "this is not a valid zip file")
    enqueue(r.id)
    return _out(r)


@router.get("/code-reviews")
def list_reviews(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> list[dict]:
    rows = session.scalars(select(CodeReview).where(CodeReview.org_id == user.org_id)
                           .order_by(CodeReview.created_at.desc()).limit(100)).all()
    return [_out(r) for r in rows]


@router.get("/code-reviews/{review_id}")
def get_review(review_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    r = session.get(CodeReview, review_id)
    if r is None or r.org_id != user.org_id:
        raise HTTPException(404, "review not found")
    return _out(r, detail=True)
