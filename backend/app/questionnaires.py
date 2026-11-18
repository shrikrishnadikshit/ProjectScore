"""Vendor security questionnaires.

A customer sends a questionnaire to a vendor in its portfolio. The vendor answers through a private link
without needing an account. Answers are scored, and checked against what the scanner sees from outside:
a "Yes" that our findings contradict is flagged, which is something a questionnaire alone cannot do.
"""

from __future__ import annotations

import os
import secrets
import threading
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import Finding, Questionnaire, QuestionnaireProfile, User, VendorOnboarding
from .optout import _EMAIL_RE

router = APIRouter(prefix="/api")
EXPIRES = timedelta(days=60)
ANSWERS = ("yes", "partial", "no", "na")

# (id, section, question, finding codes or risk factors that contradict a "yes")
QUESTIONS: list[tuple[str, str, str, list[str]]] = [
    ("gov1", "Governance", "Do you have an information security policy approved by management and reviewed at least yearly?", []),
    ("gov2", "Governance", "Is a named person responsible for information security?", []),
    ("gov3", "Governance", "Are you certified to ISO/IEC 27001 or audited against SOC 2 or a similar standard?", []),
    ("acc1", "Access control", "Is multi-factor authentication required for all remote and administrative access?", ["rdp_exposed", "vnc_exposed", "telnet_exposed"]),
    ("acc2", "Access control", "Are user accounts removed within one working day when staff leave?", []),
    ("acc3", "Access control", "Are privileged accounts reviewed at least every quarter?", []),
    ("data1", "Data protection", "Is customer data encrypted in transit with TLS 1.2 or later?", ["tls"]),
    ("data2", "Data protection", "Is customer data encrypted at rest?", []),
    ("data3", "Data protection", "Do you know where customer data is stored, including by your own suppliers?", []),
    ("mail1", "Email security", "Do you publish SPF and an enforced DMARC policy (quarantine or reject) for your domains?", ["spf_missing", "spf_pass_all", "spf_weak", "dmarc_missing", "dmarc_monitor_only", "dmarc_partial"]),
    ("vuln1", "Vulnerability management", "Are critical security patches applied within 14 days?", ["vulnerability"]),
    ("vuln2", "Vulnerability management", "Is an external penetration test done at least yearly?", []),
    ("vuln3", "Vulnerability management", "Are internet-facing systems scanned for vulnerabilities at least monthly?", ["vulnerability", "network_exposure"]),
    ("net1", "Network security", "Are databases, remote desktop and admin interfaces kept off the public internet?", ["network_exposure"]),
    ("web1", "Application security", "Do your web applications follow secure development practices (for example OWASP ASVS)?", ["web_security"]),
    ("mon1", "Monitoring", "Are security logs collected centrally and kept for at least 180 days?", []),
    ("mon3", "Monitoring", "Do you monitor the dark web for your leaked data and staff logins stolen by malware, and act on what you find?", []),
    ("mon2", "Monitoring", "Do you monitor for malware and compromised systems around the clock?", ["compromise"]),
    ("ir1", "Incident response", "Do you have a tested incident response plan?", []),
    ("ir2", "Incident response", "Will you notify us within 24 hours of a security incident affecting our data?", []),
    ("ir3", "Incident response", "Can you report incidents to CERT-In within 6 hours as required?", []),
    ("bcp1", "Business continuity", "Are backups tested and kept offline or immutable?", []),
    ("bcp2", "Business continuity", "Is a business continuity plan tested at least yearly?", []),
    ("ppl1", "People", "Do all staff complete security awareness training, including phishing, every year?", []),
    ("ai1", "AI security", "Do you keep an inventory of the AI systems and AI services you use, with an approved AI use policy?", []),
    ("ai2", "AI security", "Is our data kept out of AI model training, and do you know which AI providers process it?", []),
    ("ai3", "AI security", "Are your AI features tested for prompt injection and the other OWASP Top 10 risks for LLM applications?", []),
    ("ai4", "AI security", "Are AI model servers, notebooks and vector databases kept off the public internet and protected by authentication?", ["ai_service_exposed"]),
    ("sup1", "Supply chain", "Do you assess the security of your own critical suppliers?", []),
]
QUESTION_IDS = {q[0] for q in QUESTIONS}


def template(ids: list[str] | None = None) -> list[dict]:
    keep = set(ids) if ids is not None else QUESTION_IDS
    return [{"id": i, "section": s, "text": t} for i, s, t, _ in QUESTIONS if i in keep]


def _profile(session: Session, q: Questionnaire) -> QuestionnaireProfile | None:
    return session.scalars(select(QuestionnaireProfile).where(QuestionnaireProfile.questionnaire_id == q.id)).first()


def selected(session: Session, q: Questionnaire) -> list[str]:
    """The question ids this questionnaire asks: a tailored set when it was sent after onboarding intake."""
    p = _profile(session, q)
    return [i for i in (p.question_ids or []) if i in QUESTION_IDS] if p and p.question_ids else [x[0] for x in QUESTIONS]


def score_answers(answers: dict, ids: list[str] | None = None) -> int | None:
    points = {"yes": 1.0, "partial": 0.5, "no": 0.0}
    rated = [points[a["answer"]] for k, a in answers.items()
             if a.get("answer") in points and (ids is None or k in ids)]
    return round(100 * sum(rated) / len(rated)) if rated else None


def contradictions(answers: dict, findings: list) -> list[dict]:
    out = []
    for qid, _, text, checks in QUESTIONS:
        if not checks or answers.get(qid, {}).get("answer") != "yes":
            continue
        hits = [f for f in findings if f.code in checks or f.risk_factor in checks
                or any(f.code.startswith(c + "_") for c in checks)]
        if hits:
            out.append({"question": qid, "text": text,
                        "findings": [{"title": f.title, "severity": f.severity, "asset": f.asset_value} for f in hits[:5]],
                        "more": max(0, len(hits) - 5)})
    return out


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _out(session: Session, q: Questionnaire, detail: bool = False) -> dict:
    ids = selected(session, q)
    answers = {k: v for k, v in (q.answers or {}).items() if k in ids}
    profile = _profile(session, q)
    out = {"id": q.id, "entity_id": q.entity_id, "recipient_email": q.recipient_email, "recipient_name": q.recipient_name,
           "status": q.status, "created_at": _aware(q.created_at).isoformat(),
           "submitted_at": _aware(q.submitted_at).isoformat() if q.submitted_at else None,
           "answered": sum(1 for a in answers.values() if a.get("answer")), "total": len(ids),
           "tailored": bool(profile and profile.question_ids), "ai_runs": profile.ai_runs if profile else 0,
           "score": score_answers(answers) if q.status in ("submitted", "reviewed") else None,
           "link_path": f"/q/{q.token}"}
    if detail:
        findings = session.scalars(select(Finding).where(Finding.entity_id == q.entity_id, Finding.status == "open")).all()
        out["questions"] = template(ids)
        out["reasons"] = (profile.reasons or {}) if profile else {}
        out["documents"] = (profile.documents or []) if profile else []
        out["answers"] = answers
        out["reviewer_note"] = q.reviewer_note
        out["contradictions"] = contradictions(answers, findings) if q.status in ("submitted", "reviewed") else []
    return out


class SendIn(BaseModel):
    recipient_email: str
    recipient_name: str | None = None

    @field_validator("recipient_email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.strip()
        if not _EMAIL_RE.match(v):
            raise ValueError("not a valid email")
        return v


def _email_link(q: Questionnaire, entity_name: str, org_name: str, count: int | None = None) -> None:
    if not (os.environ.get("RESEND_API_KEY") and os.environ.get("ALERT_EMAIL_FROM")):
        return
    import httpx

    base = os.environ.get("APP_URL", "https://projectscore.onrender.com").rstrip("/")
    body = (f"{org_name} has asked {entity_name} to complete a short security questionnaire "
            f"({count or len(QUESTIONS)} questions, about 15 minutes).\n\nOpen it here: {base}/q/{q.token}\n\n"
            "You can save your answers and come back later. The link expires in 60 days.")
    try:
        httpx.post("https://api.resend.com/emails", timeout=20.0,
                   headers={"Authorization": f"Bearer {os.environ['RESEND_API_KEY']}"},
                   json={"from": os.environ["ALERT_EMAIL_FROM"], "to": [q.recipient_email],
                         "subject": f"Security questionnaire from {org_name}", "text": body}).raise_for_status()
    except httpx.HTTPError:
        pass


@router.post("/entities/{entity_id}/questionnaires", status_code=201)
def send_questionnaire(entity_id: int, body: SendIn, user: User = Depends(auth.require_admin),
                       session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    item = _portfolio_item(session, user, entity_id)
    q = Questionnaire(org_id=user.org_id, entity_id=entity_id, token=secrets.token_urlsafe(24),
                      recipient_email=body.recipient_email, recipient_name=(body.recipient_name or "").strip() or None,
                      created_by=user.id, answers={})
    session.add(q)
    session.flush()
    count = None
    ob = session.scalars(select(VendorOnboarding).where(VendorOnboarding.org_id == user.org_id,
                                                        VendorOnboarding.entity_id == entity_id)).first()
    if ob and ob.tier:
        from .smartq import select_questions

        ids, reasons = select_questions([x[0] for x in QUESTIONS], ob.tier, ob.intake)
        session.add(QuestionnaireProfile(questionnaire_id=q.id, question_ids=ids, reasons=reasons, drafts={}, documents=[]))
        count = len(ids)
    session.commit()
    threading.Thread(target=_email_link, args=(q, item.entity.name, user.org.name, count), daemon=True).start()
    return _out(session, q)


@router.get("/entities/{entity_id}/questionnaires")
def list_questionnaires(entity_id: int, user: User = Depends(auth.current_user),
                        session: Session = Depends(db.get_session)) -> list[dict]:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    rows = session.scalars(select(Questionnaire).where(Questionnaire.org_id == user.org_id,
                                                       Questionnaire.entity_id == entity_id)
                           .order_by(Questionnaire.created_at.desc())).all()
    return [_out(session, q) for q in rows]


def _own(session: Session, user: User, qid: int) -> Questionnaire:
    q = session.get(Questionnaire, qid)
    if q is None or q.org_id != user.org_id:
        raise HTTPException(404, "questionnaire not found")
    return q


@router.get("/questionnaires/{qid}")
def get_questionnaire(qid: int, user: User = Depends(auth.current_user),
                      session: Session = Depends(db.get_session)) -> dict:
    return _out(session, _own(session, user, qid), detail=True)


class ReviewIn(BaseModel):
    note: str | None = None


@router.post("/questionnaires/{qid}/review")
def review_questionnaire(qid: int, body: ReviewIn, user: User = Depends(auth.require_admin),
                         session: Session = Depends(db.get_session)) -> dict:
    q = _own(session, user, qid)
    if q.status not in ("submitted", "reviewed"):
        raise HTTPException(409, "the vendor has not submitted this questionnaire yet")
    q.status, q.reviewer_note = "reviewed", (body.note or "").strip()[:2000] or None
    session.commit()
    return _out(session, q, detail=True)


def _by_token(session: Session, token: str) -> Questionnaire:
    q = session.scalars(select(Questionnaire).where(Questionnaire.token == token)).first()
    if q is None or datetime.now(timezone.utc) - _aware(q.created_at) > EXPIRES:
        raise HTTPException(404, "this link is not valid or has expired")
    return q


@router.get("/public/questionnaire/{token}")
def public_get(token: str, session: Session = Depends(db.get_session)) -> dict:
    q = _by_token(session, token)
    from .models import Entity, Organization

    entity, org = session.get(Entity, q.entity_id), session.get(Organization, q.org_id)
    from .smartq import MAX_RUNS, ai_enabled

    profile = _profile(session, q)
    runs = profile.ai_runs if profile else 0
    return {"company": entity.name if entity else None, "requested_by": org.name if org else None,
            "status": q.status, "questions": template(selected(session, q)), "answers": q.answers or {},
            "drafts": (profile.drafts or {}) if profile else {}, "documents": (profile.documents or []) if profile else [],
            "ai": {"available": ai_enabled(), "runs_left": max(0, MAX_RUNS - runs)}}


class AnswersIn(BaseModel):
    answers: dict[str, dict]
    submit: bool = False


@router.put("/public/questionnaire/{token}")
def public_save(token: str, body: AnswersIn, session: Session = Depends(db.get_session)) -> dict:
    q = _by_token(session, token)
    if q.status in ("submitted", "reviewed"):
        raise HTTPException(409, "this questionnaire has already been submitted")
    ids = selected(session, q)
    clean = {}
    for qid, a in body.answers.items():
        if qid not in ids:
            continue
        answer = a.get("answer")
        clean[qid] = {"answer": answer if answer in ANSWERS else None,
                      "comment": str(a.get("comment") or "")[:2000]}
    if body.submit and sum(1 for a in clean.values() if a["answer"]) < len(ids):
        raise HTTPException(422, "please answer every question before submitting (use N/A where it does not apply)")
    q.answers = clean
    q.status = "submitted" if body.submit else "in_progress"
    if body.submit:
        q.submitted_at = datetime.now(timezone.utc)
    session.commit()
    return {"status": q.status}


@router.post("/public/questionnaire/{token}/documents")
async def public_documents(token: str, files: list[UploadFile] = File(...), session: Session = Depends(db.get_session)) -> dict:
    """Draft answers from the vendor's own documents with AI. The files are read once and not stored."""
    from fastapi.concurrency import run_in_threadpool

    from . import smartq

    q = _by_token(session, token)
    if q.status in ("submitted", "reviewed"):
        raise HTTPException(409, "this questionnaire has already been submitted")
    if not smartq.ai_enabled():
        raise HTTPException(503, "AI drafting is not switched on for this service")
    if not files or len(files) > smartq.MAX_FILES:
        raise HTTPException(422, f"upload 1 to {smartq.MAX_FILES} files")
    profile = _profile(session, q)
    if profile is None:
        profile = QuestionnaireProfile(questionnaire_id=q.id, question_ids=[], reasons={}, drafts={}, documents=[], ai_runs=0)
        session.add(profile)
    if (profile.ai_runs or 0) >= smartq.MAX_RUNS:
        raise HTTPException(429, "AI drafting has been used the maximum number of times for this questionnaire")
    loaded = []
    for f in files:
        data = await f.read(smartq.MAX_BYTES + 1)
        name = (f.filename or "document")[:200]
        if len(data) > smartq.MAX_BYTES:
            raise HTTPException(413, f"{name} is larger than 10 MB")
        if data[:5] == b"%PDF-":
            media = "application/pdf"
        elif name.lower().endswith((".txt", ".md")):
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                raise HTTPException(422, f"{name} is not a readable text file")
            media = "text/plain"
        else:
            raise HTTPException(422, f"{name}: only PDF and plain text files can be read")
        loaded.append((name, media, data))
    profile.ai_runs = (profile.ai_runs or 0) + 1
    session.commit()
    try:
        drafts = await run_in_threadpool(smartq.draft_answers, template(selected(session, q)), loaded)
    except Exception:  # noqa: BLE001 - logged; the vendor sees a retryable failure
        import logging

        logging.getLogger(__name__).exception("questionnaire AI drafting failed")
        raise HTTPException(502, "could not draft answers from these documents, please try again later")
    profile.drafts = {**(profile.drafts or {}), **drafts}
    profile.documents = (profile.documents or []) + [{"name": n, "size": len(d)} for n, _, d in loaded]
    session.commit()
    return {"drafts": profile.drafts, "documents": profile.documents, "runs_left": max(0, smartq.MAX_RUNS - profile.ai_runs)}
