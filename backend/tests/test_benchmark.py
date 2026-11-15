from fastapi.testclient import TestClient

from app import auth, db, main
from app.auth import create_user
from app.collectors import RawFinding
from app.models import Entity
from app.scan import scan_entity

PASSWORD = "correct-horse-battery"


def setup_function():
    auth.throttle._failures.clear()
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)
    s = db.SessionLocal()
    create_user(s, "Client", "admin@c.example", PASSWORD, role="admin")
    s.close()


def test_benchmark_groups_and_privacy():
    c = TestClient(main.app)
    c.post("/api/auth/login", json={"email": "admin@c.example", "password": PASSWORD})
    s = db.SessionLocal()
    ids = []
    for i in range(6):
        e = Entity(name=f"B{i}", primary_domain=f"b{i}.example", industry="Banking" if i < 4 else "Telecom")
        s.add(e)
        s.commit()
        raw = [RawFinding("tls", "cert_expired", "x", "high", f"h{j}.b{i}.example") for j in range(i)]
        scan_entity(s, e, lambda x, raw=raw: (raw, {"tls": 6}))
        ids.append(e.id)
    s.close()
    eid = c.post("/api/entities", json={"name": "B0", "primary_domain": "b0.example"}).json()["id"]
    b = c.get(f"/api/entities/{eid}/benchmark").json()
    assert b["platform"]["count"] == 6 and b["platform"]["percentile"] == 100  # best of six
    assert b["industry"] == "Banking" and b["industry_group"]["count"] == 4 and b["industry_group"]["median"] is None

    assert c.patch(f"/api/entities/{eid}/industry", json={"industry": "Made up"}).status_code == 422
    assert c.patch(f"/api/entities/{eid}/industry", json={"industry": "Telecom"}).json() == {"industry": "Telecom"}
    assert c.get(f"/api/entities/{eid}/benchmark").json()["industry_group"]["count"] == 3
    assert c.get(f"/api/entities/{ids[1]}/benchmark").status_code == 404  # not in this portfolio
