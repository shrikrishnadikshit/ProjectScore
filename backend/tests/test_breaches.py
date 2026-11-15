from datetime import date, datetime, timezone

from app.collectors import breaches
from app.scoring import ScoringFinding, decay

ROWS = [
    {"Name": "Acme2025", "Domain": "acme.example", "BreachDate": "2025-06-01", "PwnCount": 120000,
     "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True},
    {"Name": "AcmeShop", "Domain": "shop.acme.example", "BreachDate": "2022-01-10", "PwnCount": 5000,
     "DataClasses": ["Email addresses"], "IsVerified": False},
    {"Name": "AcmeOld", "Domain": "acme.example", "BreachDate": "2012-01-01", "PwnCount": 1, "DataClasses": []},
    {"Name": "Fake", "Domain": "acme.example", "BreachDate": "2025-01-01", "IsFabricated": True},
    {"Name": "Other", "Domain": "notacme.example", "BreachDate": "2025-01-01"},
]


def test_breach_matching():
    fs = breaches.evaluate("acme.example", ROWS, today=date(2026, 11, 15))
    assert [(f.code, f.severity) for f in fs] == [("breach_acme2025", "high"), ("breach_acmeshop", "low")]
    assert fs[1].detection_confidence == 0.6 and fs[0].evidence["event_date"] == "2025-06-01"
    assert breaches.collect("acme.example", rows=[]) == ([], 1)


def test_breach_decays_from_event_date_while_open():
    now = datetime(2026, 11, 15, tzinfo=timezone.utc)
    f = ScoringFinding("breach_history", "high", "acme.example", status="open",
                       evidence={"event_date": "2025-11-15"})
    assert abs(decay(f, now) - 0.5) < 0.01  # one 365-day half-life
    assert decay(ScoringFinding("tls", "high", "x", status="open"), now) == 1.0
