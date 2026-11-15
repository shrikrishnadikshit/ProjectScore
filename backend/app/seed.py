"""Load fictional demo companies so the web app can be explored without live scanning.

Usage: python -m app.seed   (uses DATABASE_URL, default sqlite:///./projectscore.db)
All domains use reserved example names and the findings are made up.
"""

from datetime import timedelta

from sqlalchemy import select

from . import db
from .collectors import RawFinding as R
from .models import Entity, Score
from .scan import scan_entity
from .scoring import grade_for

COVER = {"email_security": 1, "dns_health": 3, "tls": 3, "web_security": 3}

DEMO = [
    ("Northwind Logistics", "northwind.example", "Logistics", 1, [
        R("email_security", "dmarc_missing", "No DMARC record", "high", "northwind.example"),
        R("tls", "cert_expired", "Certificate has expired", "high", "portal.northwind.example"),
        R("dns_health", "dangling_cname", "CNAME points to a name that does not resolve", "high",
          "shop.northwind.example", {"cname": "old-shop.cloudhost.example"}, 0.7),
        R("web_security", "csp_missing", "No Content-Security-Policy header", "low", "northwind.example"),
    ]),
    ("Contoso Payments", "contoso.example", "Financial services", 1, [
        R("email_security", "mta_sts_missing", "No MTA-STS policy", "low", "contoso.example"),
        R("tls", "hsts_missing", "No HSTS header", "low", "www.contoso.example"),
    ]),
    ("Fabrikam Cloud", "fabrikam.example", "Technology", 2, [
        R("email_security", "dmarc_monitor_only", "DMARC policy is p=none", "medium", "fabrikam.example"),
        R("tls", "tls_old_protocol", "Server negotiated outdated TLSv1.1", "medium", "legacy.fabrikam.example"),
        R("web_security", "cookie_flags", "Cookie without Secure/HttpOnly flags", "low", "fabrikam.example"),
        R("web_security", "xfo_missing", "No clickjacking protection", "low", "fabrikam.example"),
    ]),
    ("Tailspin Health", "tailspin.example", "Healthcare", 2, []),
    ("Adatum Retail", "adatum.example", "Retail", 3, [
        R("email_security", "spf_pass_all", "SPF allows any sender (+all)", "high", "adatum.example"),
        R("email_security", "dmarc_missing", "No DMARC record", "high", "adatum.example"),
        R("tls", "cert_untrusted", "Certificate is not trusted or does not match", "high", "adatum.example"),
        R("tls", "cert_untrusted", "Certificate is not trusted or does not match", "high", "www.adatum.example"),
        R("web_security", "csp_missing", "No Content-Security-Policy header", "low", "adatum.example"),
    ]),
]


def main() -> None:
    db.Base.metadata.create_all(db.engine)
    session = db.SessionLocal()
    for name, domain, industry, tier, findings in DEMO:
        if session.scalars(select(Entity).where(Entity.primary_domain == domain)).first():
            continue
        entity = Entity(name=name, primary_domain=domain, industry=industry, tier=tier)
        session.add(entity)
        session.commit()
        latest = scan_entity(session, entity, lambda e, raw=findings: (raw, COVER))
        # Two earlier, illustrative history points so the trend chart has something to show.
        for days_ago, delta in ((14, -35), (7, -15)):
            overall = max(300, min(900, latest.overall + delta))
            session.add(Score(entity_id=entity.id, overall=overall, grade=grade_for(overall),
                              model_version=latest.model_version, factors=latest.factors,
                              trace={"contributions": [], "gates": [], "demo": True},
                              created_at=latest.created_at - timedelta(days=days_ago)))
        session.commit()
    session.close()
    print("Demo data loaded:", ", ".join(d[0] for d in DEMO))


if __name__ == "__main__":
    main()
