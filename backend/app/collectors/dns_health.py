"""DNS health collector (risk factor 8): DNSSEC and dangling CNAMEs."""

from . import RawFinding
from .dns_util import LookupFailed, resolve, zone_is_reachable

FACTOR = "dns_health"


def evaluate_dnssec(domain: str, has_ds: bool) -> list[RawFinding]:
    if not has_ds:
        return [RawFinding(FACTOR, "dnssec_missing", "DNSSEC not enabled", "low", domain)]
    return []


def evaluate_dangling_cname(host: str, cname_target: str | None, target_resolves: bool) -> list[RawFinding]:
    if cname_target and not target_resolves:
        return [RawFinding(FACTOR, "dangling_cname", "CNAME points to a name that does not resolve "
                           "(possible subdomain takeover)", "high", host, {"cname": cname_target},
                           detection_confidence=0.7)]
    return []


def collect(domain: str, hosts: list[str]) -> tuple[list[RawFinding], int]:
    if not zone_is_reachable(domain):
        return [], 0
    try:
        findings = evaluate_dnssec(domain, bool(resolve(domain, "DS")))
    except LookupFailed:
        return [], 0
    assessed = 1
    for host in hosts:
        try:
            cnames = resolve(host, "CNAME")
            if cnames:
                target = str(cnames[0].target).rstrip(".")
                resolves = bool(resolve(target, "A") or resolve(target, "AAAA"))
                findings += evaluate_dangling_cname(host, target, resolves)
        except LookupFailed:
            continue
        if host != domain:
            assessed += 1
    return findings, assessed
