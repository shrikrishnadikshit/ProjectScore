import io
import json
import subprocess
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import auth, codereview, db, main
from app.auth import create_user
from app.models import CodeReview

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    create_user(s, "Client", "member@c.example", PASSWORD)
    create_user(s, "Other", "admin@o.example", PASSWORD, role="admin")
    s.close()


def login(email):
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    return c


def make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()


def test_validate_git_url():
    assert codereview.validate_git_url("https://github.com/acme/app.git/") == "https://github.com/acme/app.git"
    for bad in ("http://github.com/a/b", "https://user:pw@github.com/a/b", "https://evil.example/a/b",
                "https://github.com:8443/a/b", "file:///etc/passwd", "https://github.com/onlyowner", "ext::sh -c id"):
        with pytest.raises(ValueError):
            codereview.validate_git_url(bad)


def test_safe_extract_blocks_traversal(tmp_path):
    z = tmp_path / "bad.zip"
    z.write_bytes(make_zip({"../escape.txt": "x"}))
    with pytest.raises(ValueError):
        codereview.safe_extract(z, tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()
    good = tmp_path / "good.zip"
    good.write_bytes(make_zip({"src/app.py": "print(1)\n"}))
    codereview.safe_extract(good, tmp_path / "ok")
    assert (tmp_path / "ok" / "src" / "app.py").exists()


def test_safe_extract_limits_size(tmp_path, monkeypatch):
    monkeypatch.setattr(codereview, "MAX_EXTRACTED", 10)
    z = tmp_path / "big.zip"
    z.write_bytes(make_zip({"a.txt": "x" * 100}))
    with pytest.raises(ValueError):
        codereview.safe_extract(z, tmp_path / "out")


def fake_runner(root_holder):
    def run(cmd, **kw):
        name = cmd[0]
        root = Path(root_holder["root"])
        if name == "gitleaks":
            Path(cmd[cmd.index("--report-path") + 1]).write_text(json.dumps([
                {"RuleID": "aws-access-token", "Description": "AWS key", "File": str(root / "config.py"),
                 "StartLine": 3, "Secret": "REDACTED"}]))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if name == "osv-scanner":
            out = {"results": [{"source": {"path": str(root / "requirements.txt")}, "packages": [{
                "package": {"name": "django", "version": "3.2.0", "ecosystem": "PyPI"},
                "groups": [{"ids": ["GHSA-xxxx"], "aliases": ["CVE-2023-1234"], "max_severity": "9.8"}],
                "vulnerabilities": [{"id": "GHSA-xxxx", "summary": "SQL injection", "aliases": ["CVE-2023-1234"],
                                     "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.2.19"}]}]}]}]}]}]}
            return subprocess.CompletedProcess(cmd, 1, json.dumps(out), "")
        if name == "bandit":
            out = {"results": [
                {"test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true", "issue_severity": "HIGH",
                 "issue_confidence": "HIGH", "issue_text": "shell=True", "filename": str(root / "app.py"),
                 "line_number": 7, "more_info": "https://bandit.readthedocs.io"},
                {"test_id": "B101", "test_name": "assert_used", "issue_severity": "LOW", "issue_confidence": "LOW",
                 "issue_text": "assert", "filename": str(root / "app.py"), "line_number": 2}]}
            return subprocess.CompletedProcess(cmd, 0, json.dumps(out), "")
        raise FileNotFoundError(name)
    return run


def test_run_tools_parses_all_three(tmp_path):
    root = tmp_path / "code"
    root.mkdir()
    findings, notes = codereview.run_tools(root, runner=fake_runner({"root": root}))
    assert notes == []
    tools = {f["tool"] for f in findings}
    assert tools == {"Gitleaks", "OSV-Scanner", "Bandit"}
    assert len([f for f in findings if f["tool"] == "Bandit"]) == 1  # low/low skipped
    leak = next(f for f in findings if f["tool"] == "Gitleaks")
    assert leak["file"] == "config.py" and leak["severity"] == "high" and "REDACTED" not in json.dumps(leak).replace("redacted", "")
    osv = next(f for f in findings if f["tool"] == "OSV-Scanner")
    assert osv["severity"] == "critical" and "3.2.19" in osv["fix"] and osv["file"] == "requirements.txt"
    assert findings[0]["severity"] == "critical"


def test_missing_tool_is_noted(tmp_path):
    def runner(cmd, **kw):
        raise FileNotFoundError(cmd[0])
    findings, notes = codereview.run_tools(tmp_path, runner=runner)
    assert findings == [] and len(notes) == 3


def test_upload_flow_and_permissions(tmp_path, monkeypatch):
    monkeypatch.setattr(codereview, "WORK_DIR", tmp_path / "work")
    queued = []
    monkeypatch.setattr(codereview, "enqueue", queued.append)
    admin, member, other = login("admin@c.example"), login("member@c.example"), login("admin@o.example")
    data = make_zip({"app.py": "import subprocess\n"})
    files = {"file": ("repo.zip", data, "application/zip")}
    assert member.post("/api/code-reviews/upload", files=files, data={"confirm": "true"}).status_code == 403
    assert admin.post("/api/code-reviews/upload", files=files).status_code == 422  # no authorisation confirmed
    assert admin.post("/api/code-reviews/upload", files={"file": ("x.zip", b"not a zip", "application/zip")},
                      data={"confirm": "true"}).status_code == 422
    r = admin.post("/api/code-reviews/upload", files=files, data={"confirm": "true"})
    assert r.status_code == 202
    rid = r.json()["id"]
    assert queued == [rid]

    holder = {"root": tmp_path / "work" / str(rid) / "code"}
    codereview.process(rid, runner=fake_runner(holder))
    assert not (tmp_path / "work" / str(rid)).exists()  # code deleted after the scan
    detail = member.get(f"/api/code-reviews/{rid}").json()
    assert detail["status"] == "done" and detail["summary"]["total"] == 3
    assert detail["summary"]["by_tool"]["Gitleaks"] == 1
    assert other.get(f"/api/code-reviews/{rid}").status_code == 404
    assert other.get("/api/code-reviews").json() == []
    assert len(member.get("/api/code-reviews").json()) == 2  # the bad zip is listed as failed


def test_git_flow_quota_and_bad_links(tmp_path, monkeypatch):
    monkeypatch.setattr(codereview, "enqueue", lambda rid: None)
    admin = login("admin@c.example")
    assert admin.post("/api/code-reviews/git", json={"url": "https://evil.example/a/b", "confirm": True}).status_code == 422
    assert admin.post("/api/code-reviews/git", json={"url": "https://github.com/a/b"}).status_code == 422
    r = admin.post("/api/code-reviews/git", json={"url": "https://github.com/acme/app", "confirm": True})
    assert r.status_code == 202 and r.json()["name"] == "acme/app"
    monkeypatch.setattr(codereview, "DAILY_LIMIT", 1)
    assert admin.post("/api/code-reviews/git", json={"url": "https://github.com/acme/app", "confirm": True}).status_code == 429


def test_failed_clone_and_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(codereview, "WORK_DIR", tmp_path / "work")
    monkeypatch.setattr(codereview, "is_public_host", lambda h: True)
    s = db.SessionLocal()
    r = CodeReview(org_id=1, name="a/b", source_type="git", source="https://github.com/a/b")
    stuck = CodeReview(org_id=1, name="c/d", source_type="git", source="https://github.com/c/d", status="running")
    s.add_all([r, stuck])
    s.commit()
    rid, sid = r.id, stuck.id
    codereview.process(rid, runner=lambda cmd, **kw: subprocess.CompletedProcess(cmd, 128, "", "not found"))
    codereview.fail_interrupted(s)
    s.expire_all()
    assert s.get(CodeReview, rid).status == "failed" and "cloned" in s.get(CodeReview, rid).error
    assert s.get(CodeReview, sid).status == "failed"
    s.close()


def test_best_fix_stays_on_release_line():
    assert codereview._best_fix("3.2.0", ["4.1.10", "3.2.19", "4.0.2"]) == "3.2.19"
    assert codereview._fixed_versions({"affected": [{"ranges": [{"events": [{"fixed": "3.2.10"}, {"fixed": "3.2.9"}]}]}]}) == ["3.2.9", "3.2.10"]
