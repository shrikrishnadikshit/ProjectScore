from datetime import datetime, timedelta, timezone

from app import db, scheduler
from app.models import Entity, Organization, PortfolioItem, Score


def test_due_entities_are_monitored_and_stale():
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    now = datetime(2026, 12, 1, tzinfo=timezone.utc)
    org = Organization(name="O")
    s.add(org)
    s.flush()
    ents = {}
    for name, age_days, monitored in [("stale", 8, True), ("fresh", 2, True), ("unmonitored", 30, False),
                                      ("older", 20, True)]:
        e = Entity(name=name, primary_domain=f"{name}.example")
        s.add(e)
        s.flush()
        ents[name] = e.id
        s.add(Score(entity_id=e.id, overall=800, grade="A", model_version="1", factors={}, trace={},
                    created_at=now - timedelta(days=age_days)))
        s.add(Score(entity_id=e.id, overall=800, grade="A", model_version="1", factors={}, trace={},
                    created_at=now - timedelta(days=age_days + 7)))
        if monitored:
            s.add(PortfolioItem(org_id=org.id, entity_id=e.id))
    never = Entity(name="never", primary_domain="never.example")
    s.add(never)
    s.flush()
    s.add(PortfolioItem(org_id=org.id, entity_id=never.id))
    s.commit()
    assert scheduler.due_entity_ids(s, now) == [ents["older"], ents["stale"]]
    s.close()
