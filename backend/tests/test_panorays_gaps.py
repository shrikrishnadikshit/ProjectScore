from datetime import date

import httpx
import pytest
from fastapi.testclient import TestClient

from app import auth, db, integrations, main, onboarding, smartq
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Alert, Entity, OrgIntegration, VendorOnboarding
from app.questionnaires import QUESTIONS
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"
ALL = [q[0] for q in QUESTIONS]
LOW = {"data": "none", "volume": "none", "access": "none", "criticality": "low", "hosting": "no",
       "offshore": "no", "ai": "no", "subcontractors": "no", "regulated": "no"}
HIGH = {**LOW, "data": "financial", "volume": "large", "access": "read", "criticality": "high", "hosting": "yes",
        "ai": "yes", "subcontractors": "yes", "regulated": "yes"}


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


def add_vendor(c, domain="vendor.example"):
    return c.post("/api/entities", json={"name": "V", "primary_domain": domain}).json()["id"]


# ---------- tiering ----------

def test_inherent_tiering():
    assert onboarding.inherent({}) == (None, None, None)
    score, tier, level = onboarding.inherent(LOW)
    assert (score, tier, level) == (0, 3, "low")
    score, tier, level = onboarding.inherent(HIGH)
    assert tier == 1 and level in ("high", "critical")
    # admin access alone makes the vendor critical
    assert onboarding.inherent({**LOW, "access": "admin"})[1:] == (1, "critical")


def test_onboarding_flow():
    admin, member, other = login("admin@c.example"), login("member@c.example"), login("admin@o.example")
    eid = add_vendor(admin)
    assert member.post("/api/onboarding", json={"entity_id": eid}).status_code == 403
    ob = admin.post("/api/onboarding", json={"entity_id": eid, "intake": {"data": "internal"}}).json()
    assert ob["tier"] is None and ob["stage"] == "intake"
    assert admin.post("/api/onboarding", json={"entity_id": eid}).status_code == 409
    assert admin.post(f"/api/onboarding/{ob['id']}/action", json={"action": "start_assessment"}).status_code == 422
    ob = admin.put(f"/api/onboarding/{ob['id']}/intake", json={"intake": HIGH}).json()
    assert ob["tier"] == 1 and len(ob["requirements"]) == 4
    assert other.get(f"/api/onboarding/{ob['id']}").status_code == 404
    ob = admin.post(f"/api/onboarding/{ob['id']}/action", json={"action": "start_assessment"}).json()
    assert ob["stage"] == "assessment"
    assert {c["check"] for c in ob["checks"]} >= {"Security questionnaire answered", "No open critical issues"}
    assert admin.post(f"/api/onboarding/{ob['id']}/action", json={"action": "reject"}).status_code == 422
    assert admin.post(f"/api/onboarding/{ob['id']}/action", json={"action": "reopen"}).status_code == 409
    ob = admin.post(f"/api/onboarding/{ob['id']}/action",
                    json={"action": "approve_with_conditions", "note": "Fix DMARC in 30 days"}).json()
    assert ob["stage"] == "conditional" and ob["next_review"] and [h["action"] for h in ob["history"]][-1] == "approve with conditions"
    listing = member.get("/api/onboarding").json()
    assert listing["items"][0]["tier"] == 1 and listing["due"] == 0

    s = db.SessionLocal()
    row = s.get(VendorOnboarding, ob["id"])
    due = row.next_review
    assert onboarding.review_reminders(s, due) == 1
    assert onboarding.review_reminders(s, due) == 0  # one alert per day
    assert s.query(Alert).filter_by(kind="reassessment_due").count() == 1
    assert onboarding.review_reminders(s, date(2000, 1, 1)) == 0
    s.close()


# ---------- smart questionnaires ----------

def test_select_questions():
    assert smartq.select_questions(ALL, None, None)[0] == ALL
    low, _ = smartq.select_questions(ALL, 3, LOW)
    assert set(low) == smartq.CORE
    mid, reasons = smartq.select_questions(ALL, 2, {**LOW, "data": "personal"})
    assert "data2" in mid and "ai1" not in mid and "vuln2" not in mid and "sup1" not in mid
    high, reasons = smartq.select_questions(ALL, 1, HIGH)
    assert set(high) == set(ALL) and reasons["ai1"].startswith("The vendor will use AI")
    assert high == [q for q in ALL if q in high]  # template order kept


def test_tailored_questionnaire_and_ai_drafts(monkeypatch):
    admin = login("admin@c.example")
    eid = add_vendor(admin)
    ob = admin.post("/api/onboarding", json={"entity_id": eid, "intake": LOW}).json()
    assert ob["tier"] == 3
    q = admin.post(f"/api/entities/{eid}/questionnaires", json={"recipient_email": "sec@vendor.example"}).json()
    assert q["tailored"] and q["total"] == len(smartq.CORE)
    token = q["link_path"].split("/")[-1]
    vendor = TestClient(main.app)
    page = vendor.get(f"/api/public/questionnaire/{token}").json()
    assert {x["id"] for x in page["questions"]} == smartq.CORE and page["ai"]["available"] is False

    # AI drafting is off without a key
    files = {"files": ("policy.txt", b"We enforce MFA for all remote access.", "text/plain")}
    assert vendor.post(f"/api/public/questionnaire/{token}/documents", files=files).status_code == 503

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    seen = {}

    def fake(questions, loaded, client=None):
        seen["q"], seen["files"] = [x["id"] for x in questions], loaded
        return {"acc1": {"answer": "yes", "evidence": "We enforce MFA", "document": "policy.txt", "confidence": "high"}}

    monkeypatch.setattr(smartq, "draft_answers", fake)
    bad = {"files": ("x.exe", b"MZ\x90", "application/octet-stream")}
    assert vendor.post(f"/api/public/questionnaire/{token}/documents", files=bad).status_code == 422
    r = vendor.post(f"/api/public/questionnaire/{token}/documents", files=files).json()
    assert r["drafts"]["acc1"]["answer"] == "yes" and r["documents"] == [{"name": "policy.txt", "size": 37}]
    assert set(seen["q"]) == smartq.CORE and seen["files"][0][1] == "text/plain"

    # answers outside the tailored set are dropped; submit needs only the selected questions
    answers = {qid: {"answer": "yes"} for qid in ALL}
    assert vendor.put(f"/api/public/questionnaire/{token}", json={"answers": answers, "submit": True}).json()["status"] == "submitted"
    detail = admin.get(f"/api/questionnaires/{q['id']}").json()
    assert set(detail["answers"]) == smartq.CORE and detail["score"] == 100 and detail["reasons"]["gov1"]
    assert vendor.post(f"/api/public/questionnaire/{token}/documents", files=files).status_code == 409


def test_ai_run_cap(monkeypatch):
    admin = login("admin@c.example")
    eid = add_vendor(admin)
    q = admin.post(f"/api/entities/{eid}/questionnaires", json={"recipient_email": "sec@vendor.example"}).json()
    assert not q["tailored"] and q["total"] == len(QUESTIONS)
    token = q["link_path"].split("/")[-1]
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    monkeypatch.setattr(smartq, "draft_answers", lambda q, f, client=None: {})
    vendor = TestClient(main.app)
    pdf = {"files": ("report.pdf", b"%PDF-1.4 fake", "application/pdf")}
    for _ in range(smartq.MAX_RUNS):
        assert vendor.post(f"/api/public/questionnaire/{token}/documents", files=pdf).status_code == 200
    assert vendor.post(f"/api/public/questionnaire/{token}/documents", files=pdf).status_code == 429


def test_draft_answers_parses_structured_output():
    class Block:
        type = "text"
        text = ('{"drafts":[{"question_id":"acc1","answer":"yes","evidence":"MFA is enforced","document":"p.pdf",'
                '"confidence":"high"},{"question_id":"zzz","answer":"yes","evidence":"","document":"","confidence":"low"},'
                '{"question_id":"gov1","answer":"unknown","evidence":"","document":"","confidence":"maybe"}]}')

    class Resp:
        stop_reason = "end_turn"
        content = [Block()]

    calls = {}

    class Client:
        class beta:
            class messages:
                @staticmethod
                def create(**kw):
                    calls.update(kw)
                    return Resp()

    out = smartq.draft_answers([{"id": "acc1", "text": "MFA?"}, {"id": "gov1", "text": "Policy?"}],
                               [("p.pdf", "application/pdf", b"%PDF-1.4")], client=Client)
    assert out["acc1"]["answer"] == "yes" and out["gov1"] == {"answer": None, "evidence": "", "document": "", "confidence": "low"}
    assert "zzz" not in out
    doc = calls["messages"][0]["content"][0]
    assert doc["type"] == "document" and doc["source"]["media_type"] == "application/pdf"
    assert calls["output_config"]["format"]["type"] == "json_schema"


# ---------- Slack and Jira ----------

class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body = status, body or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            req = httpx.Request("POST", "https://x")
            raise httpx.HTTPStatusError("boom https://hooks.slack.com/services/SECRET", request=req,
                                        response=httpx.Response(self.status_code, request=req))

    def json(self):
        return self._body


HOOK = "https://hooks.slack.com/services/T000/B000/abcdefghijklmnopqrstuvwx"


def test_integration_settings_hide_secrets():
    admin, member = login("admin@c.example"), login("member@c.example")
    assert member.put("/api/integrations/slack", json={"webhook_url": HOOK}).status_code == 403
    assert admin.put("/api/integrations/slack", json={"webhook_url": "https://evil.example/hook"}).status_code == 422
    assert admin.put("/api/integrations/slack", json={"webhook_url": HOOK}).json()["connected"]
    assert admin.put("/api/integrations/jira", json={"site": "https://evil.example", "email": "a@b.c", "project": "SEC",
                                                     "api_token": "t"}).status_code == 422
    r = admin.put("/api/integrations/jira", json={"site": "https://acme.atlassian.net/", "email": "a@acme.example",
                                                  "project": "sec", "api_token": "tok-123"})
    assert r.status_code == 200 and r.json()["config"]["project"] == "SEC"
    listing = member.get("/api/integrations")
    assert listing.json()["slack"]["connected"] and "tok-123" not in listing.text and HOOK not in listing.text
    # updating without a token keeps the stored one
    assert admin.put("/api/integrations/jira", json={"site": "https://acme.atlassian.net", "email": "a@acme.example",
                                                     "project": "OPS"}).status_code == 200
    s = db.SessionLocal()
    assert s.query(OrgIntegration).filter_by(kind="jira").one().secret == "tok-123"
    s.close()
    assert admin.delete("/api/integrations/slack").status_code == 204
    assert member.get("/api/integrations").json()["slack"]["connected"] is False


def test_slack_notify_and_error_has_no_secret():
    admin = login("admin@c.example")
    admin.put("/api/integrations/slack", json={"webhook_url": HOOK})
    s = db.SessionLocal()
    org_id = s.query(OrgIntegration).one().org_id
    sent = []
    assert integrations.notify_org(s, org_id, "Title", "Detail", "/alerts",
                                   poster=lambda url, json, timeout: sent.append((url, json)) or Resp())
    assert sent[0][0] == HOOK and "*Title*" in sent[0][1]["text"]
    assert not integrations.notify_org(s, org_id, "T", poster=lambda url, json, timeout: Resp(404))
    err = s.query(OrgIntegration).one().last_error
    assert err == "Slack: HTTP 404" and "SECRET" not in err
    s.close()


def test_alerts_dispatch_to_slack(monkeypatch):
    admin = login("admin@c.example")
    admin.put("/api/integrations/slack", json={"webhook_url": HOOK})
    sent = []
    monkeypatch.setenv("INTEGRATIONS", "on")
    monkeypatch.setattr(integrations, "slack_post", lambda url, text, poster=None: sent.append(text))
    monkeypatch.setattr(integrations.threading, "Thread",
                        lambda target, args, daemon: type("T", (), {"start": lambda self: target(*args)})())
    s = db.SessionLocal()
    org_id = s.query(OrgIntegration).one().org_id
    s.add(Alert(org_id=org_id, kind="score_drop", severity="critical", title="Rating fell", detail="By 80"))
    s.commit()
    s.close()
    assert sent and "Rating fell" in sent[0]


def test_jira_issue_from_finding(monkeypatch):
    admin, member = login("admin@c.example"), login("member@c.example")
    eid = add_vendor(admin)
    s = db.SessionLocal()
    scan_entity(s, s.get(Entity, eid), lambda e: (
        [RawFinding("email_security", "dmarc_missing", "No DMARC record", "high", "vendor.example")], {"email_security": 1}))
    s.close()
    assert member.post("/api/integrations/jira/issue", json={"entity_id": eid, "code": "dmarc_missing"}).status_code == 409
    admin.put("/api/integrations/jira", json={"site": "https://acme.atlassian.net", "email": "a@acme.example",
                                              "project": "SEC", "api_token": "tok"})
    posted = {}

    def poster(url, json, auth, timeout, headers):
        posted.update(url=url, json=json, auth=auth)
        return Resp(201, {"key": "SEC-7"})

    monkeypatch.setattr(integrations.httpx, "post", poster)
    r = member.post("/api/integrations/jira/issue", json={"entity_id": eid, "code": "dmarc_missing"})
    assert r.status_code == 201 and r.json() == {"key": "SEC-7", "url": "https://acme.atlassian.net/browse/SEC-7"}
    assert posted["url"] == "https://acme.atlassian.net/rest/api/3/issue" and posted["auth"] == ("a@acme.example", "tok")
    assert posted["json"]["fields"]["project"]["key"] == "SEC" and "dmarc_missing" in posted["json"]["fields"]["labels"]
    assert member.post("/api/integrations/jira/issue", json={"entity_id": eid, "code": "nothing"}).status_code == 404
    monkeypatch.setattr(integrations.httpx, "post", lambda *a, **k: Resp(400))
    assert member.post("/api/integrations/jira/issue", json={"entity_id": eid, "code": "dmarc_missing"}).status_code == 502
