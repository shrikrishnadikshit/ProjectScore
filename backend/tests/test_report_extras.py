from datetime import datetime, timedelta, timezone

from app import db
from app.models import Entity, Finding, Incident, Score
from app.report import build_pdf
from app.report_extras import gather, incident_risk

NOW = datetime(2026, 11, 18, tzinfo=timezone.utc)


def setup_function():
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)


def _entity(s, name, score, industry="Professional services", when=NOW):
    e = Entity(name=name, primary_domain=f"{name.lower().replace(' ', '')}.example", industry=industry)
    s.add(e)
    s.flush()
    s.add(Score(entity_id=e.id, overall=score, grade="B", factors={}, trace={}, model_version="1.0.0", created_at=when))
    return e


def _hist(e):
    return [{"overall": x.overall, "grade": x.grade, "model_version": x.model_version, "created_at": x.created_at.isoformat(),
             "trace": {}} for x in sorted(e.scores, key=lambda z: z.created_at)]


def test_peers_hidden_below_five_then_industry_average():
    s = db.SessionLocal()
    e = _entity(s, "Main", 760)
    for i in range(3):
        _entity(s, f"P{i}", 700)
    s.commit()
    assert gather(s, e, _hist(e), NOW)["peers"]["group"] is None
    _entity(s, "P9", 650)
    s.commit()
    p = gather(s, e, _hist(e), NOW)["peers"]
    assert p["group"] == "Professional services" and p["count"] == 5 and p["average"] == 702
    assert p["percentile"] == 80 and round(sum(b["share"] for b in p["distribution"])) == 100


def test_peers_fall_back_to_all_companies():
    s = db.SessionLocal()
    e = _entity(s, "Main", 760)
    for i in range(5):
        _entity(s, f"P{i}", 700, industry="Banking")
    s.commit()
    p = gather(s, e, _hist(e), NOW)["peers"]
    assert p["group"] == "All rated companies" and p["fallback"] is True


def test_trend_keeps_last_12_months_with_high_and_low():
    s = db.SessionLocal()
    e = _entity(s, "Main", 700, when=NOW - timedelta(days=400))
    for d, v in ((300, 720), (200, 800), (100, 690), (1, 760)):
        s.add(Score(entity_id=e.id, overall=v, grade="B", factors={}, trace={}, model_version="1.0.0", created_at=NOW - timedelta(days=d)))
    s.commit()
    t = gather(s, e, _hist(e), NOW)["trend"]
    assert len(t["points"]) == 4 and t["highest"]["score"] == 800 and t["lowest"]["score"] == 690 and t["change"] == 40


def test_incidents_from_records_breaches_and_leak_sites_within_18_months():
    s = db.SessionLocal()
    e = _entity(s, "Main", 700)
    s.add(Incident(entity_id=e.id, occurred_on=NOW - timedelta(days=30), kind="breach", description="Customer data leaked"))
    s.add(Incident(entity_id=e.id, occurred_on=NOW - timedelta(days=700), kind="breach", description="Too old to show"))
    s.add(Finding(entity_id=e.id, asset_value="x", risk_factor="breach_history", code="breach_a", title="Breach A",
                  severity="high", evidence={"event_date": "2026-02-01"}))
    s.add(Finding(entity_id=e.id, asset_value="x", risk_factor="compromise", code="ransomware_leak_g_20260601",
                  title="Named on leak site", severity="critical", evidence={"event_date": "2026-06-01"}))
    s.commit()
    events = gather(s, e, _hist(e), NOW)["incidents"]["events"]
    assert [ev["kind"] for ev in events] == ["Data breach", "Ransomware leak site", "Breach"]


def test_incident_risk_bands():
    assert incident_risk(820)["level"] == "Low" and incident_risk(650)["level"] == "Elevated"
    assert incident_risk(None) is None


def test_pdf_builds_with_and_without_extras():
    s = db.SessionLocal()
    e = _entity(s, "Main", 760)
    for i in range(5):
        _entity(s, f"P{i}", 600 + i * 40)
    s.commit()
    h = _hist(e)
    ent = {"name": "Main", "primary_domain": "main.example", "industry": None, "tier": 2, "score": 760, "grade": "B",
           "factors": {}, "findings": []}
    assert build_pdf(ent, h, "Org", now=NOW, extras=gather(s, e, h, NOW)).startswith(b"%PDF")
    assert build_pdf(ent, h, "Org", now=NOW).startswith(b"%PDF")
