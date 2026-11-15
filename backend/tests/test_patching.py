from datetime import datetime, timedelta, timezone

from app import db
from app.collectors import RawFinding
from app.models import Entity, Finding
from app.patching import summary
from app.scan import scan_entity

COVER = {"vulnerability": 1, "tls": 1}


def setup_function():
    db.Base.metadata.drop_all(db.engine)
    db.Base.metadata.create_all(db.engine)


def test_slow_patch_finding_and_summary():
    s = db.SessionLocal()
    e = Entity(name="V", primary_domain="vendor.example")
    s.add(e)
    s.commit()
    vuln = RawFinding("vulnerability", "php_eol", "PHP version no longer supported", "high", "www.vendor.example")
    other = RawFinding("vulnerability", "nginx_outdated", "Outdated nginx", "high", "api.vendor.example")
    scan_entity(s, e, lambda x: ([vuln, other], COVER))
    # Pretend both were first seen 90 days ago.
    for f in s.query(Finding).all():
        f.first_seen = datetime.now(timezone.utc) - timedelta(days=90)
    s.commit()
    scan_entity(s, e, lambda x: ([vuln], COVER))  # nginx fixed, php still open
    codes = {f.code: f.status for f in s.query(Finding).all()}
    assert codes["slow_patch_php_eol"] == "open"
    assert codes["nginx_outdated"] == "remediated"
    assert "slow_patch_nginx_outdated" not in codes
    p = summary(s.query(Finding).all())
    assert p["fixed"] == 1 and p["median_days_to_fix"] >= 89 and p["open"] == 1 and p["open_over_30_days"] == 1
    s.close()
