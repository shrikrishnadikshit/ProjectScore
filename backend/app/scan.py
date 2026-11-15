"""Runs all collectors for an entity, stores findings and a new score."""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .collectors import RawFinding, discovery, dns_health, email, tls, web
from .models import Asset, Entity, Finding, Score
from .scoring import ScoringFinding, compute_score


def hosts_for(entity: Entity) -> list[str]:
    hosts = [entity.primary_domain, f"www.{entity.primary_domain}"]
    hosts += [a.value for a in entity.assets if a.type == "subdomain" and a.value not in hosts]
    return hosts[:discovery.MAX_HOSTS]


def discover_assets(session: Session, entity: Entity, discover=None) -> None:
    """Adds newly seen subdomains as assets and refreshes last_seen on known ones."""
    discover = discover or discovery.discover_hosts
    now = datetime.now(timezone.utc)
    known = {a.value: a for a in entity.assets}
    for host in discover(entity.primary_domain):
        if host in known:
            known[host].last_seen = now
        else:
            asset = Asset(entity_id=entity.id, type="subdomain", value=host, first_seen=now, last_seen=now)
            session.add(asset)
            entity.assets.append(asset)
    session.flush()


def run_collectors(entity: Entity) -> tuple[list[RawFinding], dict[str, int]]:
    hosts = hosts_for(entity)
    email_findings, email_assessed = email.collect(entity.primary_domain)
    dns_findings, dns_hosts = dns_health.collect(entity.primary_domain, hosts)
    tls_findings, tls_hosts = tls.collect(hosts)
    web_findings, web_hosts, versioned_hosts = web.collect(hosts, domain=entity.primary_domain)
    # The vulnerability factor counts only hosts whose software version was visible: a hidden
    # version is not evidence of being patched, so it must not raise the score.
    coverage = {"email_security": email_assessed, "dns_health": dns_hosts, "tls": tls_hosts,
                "web_security": web_hosts, "vulnerability": versioned_hosts}
    # HSTS is a TLS-factor finding observed over HTTPS, so HTTPS hosts count toward TLS coverage.
    coverage["tls"] = max(tls_hosts, web_hosts)
    return email_findings + dns_findings + tls_findings + web_findings, coverage


# Finding codes produced by rules that were later found to be wrong. Existing findings with these
# codes are treated as false positives instead of decaying slowly as if they had been remediated.
RETIRED_CODES = {"cookie_flags"}


class NothingAssessed(Exception):
    pass


class OptedOut(NothingAssessed):
    """The domain owner asked not to be scanned and the request was approved."""


def scan_entity(session: Session, entity: Entity, collector=run_collectors,
                discover=None) -> Score:
    from .optout import is_opted_out

    if is_opted_out(session, entity.primary_domain):
        raise OptedOut(f"{entity.primary_domain} has opted out of scanning")
    discover_assets(session, entity, discover)
    raw, coverage = collector(entity)
    if not any(coverage.values()):
        raise NothingAssessed(f"no checks could run for {entity.primary_domain}")
    assessed = {f for f, n in coverage.items() if n > 0}
    now = datetime.now(timezone.utc)

    # v1: replace open findings with the latest observation; previous ones become remediated.
    previous = {(f.code, f.asset_value): f for f in session.scalars(
        select(Finding).where(Finding.entity_id == entity.id, Finding.status == "open"))}
    seen = set()
    for r in raw:
        key = (r.code, r.asset_value)
        seen.add(key)
        if key in previous:
            previous[key].last_seen = now
            previous[key].evidence = r.evidence
        else:
            session.add(Finding(entity_id=entity.id, asset_value=r.asset_value, risk_factor=r.risk_factor,
                                code=r.code, title=r.title, severity=r.severity,
                                detection_confidence=r.detection_confidence, evidence=r.evidence,
                                first_seen=now, last_seen=now))
    for key, f in previous.items():
        if f.code in RETIRED_CODES:
            f.status = "false_positive"
        elif key not in seen and f.risk_factor in assessed:
            f.status = "remediated"
    for f in session.scalars(select(Finding).where(Finding.entity_id == entity.id,
                                                   Finding.status == "remediated",
                                                   Finding.code.in_(RETIRED_CODES))):
        f.status = "false_positive"
    for host in hosts_for(entity):
        if not any(a.value == host for a in entity.assets):
            session.add(Asset(entity_id=entity.id, type="domain" if host == entity.primary_domain else "subdomain",
                              value=host))
    session.flush()

    all_findings = session.scalars(select(Finding).where(Finding.entity_id == entity.id)).all()
    result = compute_score(
        [ScoringFinding(risk_factor=f.risk_factor, severity=f.severity, asset_value=f.asset_value, code=f.code,
                        detection_confidence=f.detection_confidence, status=f.status, last_seen=f.last_seen,
                        evidence=f.evidence or {}) for f in all_findings],
        coverage, now=now)
    result["trace"]["coverage"] = result["coverage"]
    score = Score(entity_id=entity.id, overall=result["overall"], grade=result["grade"],
                  model_version=result["model_version"], factors=result["factors"], trace=result["trace"])
    session.add(score)
    session.commit()
    return score
