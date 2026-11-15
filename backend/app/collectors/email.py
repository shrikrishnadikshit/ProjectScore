"""Email security collector (risk factor 5). Passive DNS lookups only."""

from . import RawFinding
from .dns_util import LookupFailed, txt_records, zone_is_reachable

FACTOR = "email_security"


def evaluate_spf(domain: str, txt: list[str]) -> list[RawFinding]:
    spf = [r for r in txt if r.lower().startswith("v=spf1")]
    if not spf:
        return [RawFinding(FACTOR, "spf_missing", "No SPF record", "medium", domain)]
    if len(spf) > 1:
        return [RawFinding(FACTOR, "spf_multiple", "Multiple SPF records (invalid)", "medium", domain,
                           {"records": spf})]
    record = spf[0].lower()
    if "+all" in record.split():
        return [RawFinding(FACTOR, "spf_pass_all", "SPF allows any sender (+all)", "high", domain,
                           {"record": spf[0]})]
    if "?all" in record.split() or not any(t in record for t in ("-all", "~all")):
        return [RawFinding(FACTOR, "spf_weak", "SPF does not reject unauthorised senders", "low", domain,
                           {"record": spf[0]})]
    return []


def evaluate_dmarc(domain: str, txt: list[str]) -> list[RawFinding]:
    dmarc = [r for r in txt if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        return [RawFinding(FACTOR, "dmarc_missing", "No DMARC record", "high", domain)]
    tags = {}
    for part in dmarc[0].split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip().lower()
    policy = tags.get("p", "none")
    if policy == "none":
        return [RawFinding(FACTOR, "dmarc_monitor_only", "DMARC policy is p=none", "medium", domain,
                           {"record": dmarc[0]})]
    if policy == "quarantine" and tags.get("pct", "100") != "100":
        return [RawFinding(FACTOR, "dmarc_partial", "DMARC applies to only part of mail", "low", domain,
                           {"record": dmarc[0]})]
    return []


def evaluate_mta_sts(domain: str, txt: list[str]) -> list[RawFinding]:
    if not any(r.lower().startswith("v=stsv1") for r in txt):
        return [RawFinding(FACTOR, "mta_sts_missing", "No MTA-STS policy", "low", domain)]
    return []


def collect(domain: str) -> tuple[list[RawFinding], int]:
    """Returns findings and 1 if the factor was assessed, 0 if DNS was unreliable."""
    if not zone_is_reachable(domain):
        return [], 0
    try:
        findings = evaluate_spf(domain, txt_records(domain))
        findings += evaluate_dmarc(domain, txt_records(f"_dmarc.{domain}"))
        findings += evaluate_mta_sts(domain, txt_records(f"_mta-sts.{domain}"))
    except LookupFailed:
        return [], 0
    return findings, 1
