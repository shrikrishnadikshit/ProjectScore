"""AI security view of one company: AI services it exposes, AI providers it relies on, newly exploited
flaws in AI software, and the AI-driven attack paths that apply to it.

Everything comes from the same passive data as the rest of the platform. Exposed AI services are matched on
well-known ports, so they are reported as "possible" until the company confirms them.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import attackpaths, auth, db, threatevents
from .collectors import kev
from .models import Entity, Finding, User, VendorDetection

router = APIRouter(prefix="/api")

AI_PATH_IDS = ("exposed_ai_service", "ai_impersonation")
# Rules and guidance a customer is likely to be asked about for AI. Shown as references, not scored.
AI_FRAMEWORKS = [
    {"id": "eu_ai_act", "name": "EU AI Act", "region": "European Union",
     "note": "Risk-based law for AI systems placed on the EU market; requires cybersecurity and robustness for high-risk AI (Article 15).",
     "url": "https://artificialintelligenceact.eu/"},
    {"id": "nist_ai_rmf", "name": "NIST AI Risk Management Framework (AI RMF 1.0)", "region": "United States / global",
     "note": "Voluntary framework to govern, map, measure and manage AI risk, with a generative AI profile.",
     "url": "https://www.nist.gov/itl/ai-risk-management-framework"},
    {"id": "iso42001", "name": "ISO/IEC 42001", "region": "Global",
     "note": "Certifiable management system standard for organisations that build or use AI.",
     "url": "https://www.iso.org/standard/81230.html"},
    {"id": "owasp_llm", "name": "OWASP Top 10 for LLM Applications", "region": "Global",
     "note": "The most common weaknesses in apps built on language models, such as prompt injection and data leakage.",
     "url": "https://genai.owasp.org/llm-top-10/"},
    {"id": "mitre_atlas", "name": "MITRE ATLAS", "region": "Global",
     "note": "Catalogue of real attacker techniques against AI and machine-learning systems.",
     "url": "https://atlas.mitre.org/"},
]


def summary(entity: Entity, findings: list[Finding], vendors: list[dict], kev_entries: list[dict], days: int = 90) -> dict:
    open_f = [f for f in findings if f.status == "open"]
    exposed = [{"id": f.id, "title": f.title, "asset": f.asset_value, "severity": f.severity,
                "port": (f.evidence or {}).get("port"), "service": (f.evidence or {}).get("service")}
               for f in open_f if f.code.startswith("ai_service_exposed")]
    ai_vendors = [v for v in vendors if v.get("category") == "AI"]
    events = [e for e in threatevents.match(threatevents.recent(kev_entries, days), open_f, {entity.id: entity.name}) if e["ai"]]
    paths = [p for p in attackpaths.paths(open_f) if p["id"] in AI_PATH_IDS]
    level = ("high" if exposed and any(f["severity"] in ("critical", "high") for f in exposed)
             else "medium" if exposed or any(p["status"] != "entry_point" for p in paths) else "low")
    return {"level": level, "exposed_services": exposed, "ai_vendors": ai_vendors,
            "threat_events": [{"cve": e.get("cveID"), "name": e.get("vulnerabilityName"), "vendor": e.get("vendorProject"),
                               "product": e.get("product"), "date_added": e.get("dateAdded"),
                               "affected": bool(e["affected"])} for e in events],
            "threat_days": days, "attack_paths": paths, "frameworks": AI_FRAMEWORKS}


@router.get("/entities/{entity_id}/ai")
def entity_ai(entity_id: int, user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    from .main import _portfolio_item

    _portfolio_item(session, user, entity_id)
    entity = session.get(Entity, entity_id)
    findings = session.scalars(select(Finding).where(Finding.entity_id == entity_id, Finding.status == "open")).all()
    row = session.scalars(select(VendorDetection).where(VendorDetection.entity_id == entity_id)).first()
    return summary(entity, findings, row.vendors if row else [], kev.kev_entries())
