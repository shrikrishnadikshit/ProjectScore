"""Email security collector (risk factor 5). Passive DNS lookups only."""

import base64
from concurrent.futures import ThreadPoolExecutor

from . import RawFinding
from .dns_util import LookupFailed, resolve, txt_records, zone_is_reachable

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


# DKIM keys live at <selector>._domainkey.<domain>, and selectors cannot be listed, so we try the ones
# used by common mail providers. Not finding one is weak evidence, so that finding has low confidence.
DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "dkim", "mail", "k1", "k2", "s1", "s2",
                  "smtp", "zoho", "zmail", "mxvault", "everlytickey1", "mandrill", "pm", "sendgrid",
                  "amazonses", "protonmail", "fm1", "key1", "sig1", "mailjet", "hs1", "dkim1", "email"]


def dkim_key_bits(record: str) -> int | None:
    """Approximate RSA key size from the public key's DER length (no crypto library needed)."""
    tags = dict(p.strip().split("=", 1) for p in record.split(";") if "=" in p)
    if tags.get("k", "rsa").strip().lower() != "rsa":
        return None
    key = "".join(tags.get("p", "").split())
    if not key:
        return 0  # revoked key
    try:
        der = len(base64.b64decode(key + "=" * (-len(key) % 4)))
    except ValueError:
        return None
    return 512 if der < 120 else 1024 if der < 200 else 2048 if der < 350 else 4096


def evaluate_dkim(domain: str, found: dict[str, str]) -> list[RawFinding]:
    keys = {sel: rec for sel, rec in found.items() if "p=" in rec.replace(" ", "")}
    if not keys:
        return [RawFinding(FACTOR, "dkim_not_found", "No DKIM key found at common selectors", "low", domain,
                           {"selectors_tried": len(DKIM_SELECTORS)}, 0.5)]
    sizes = {sel: dkim_key_bits(rec) for sel, rec in keys.items()}
    live = {s: b for s, b in sizes.items() if b}
    if live and max(live.values()) < 1024:
        return [RawFinding(FACTOR, "dkim_weak_key", "DKIM key shorter than 1024 bits (forgeable)", "high", domain,
                           {"selectors": live})]
    if live and max(live.values()) < 2048:
        return [RawFinding(FACTOR, "dkim_1024", "DKIM key is only 1024 bits", "low", domain, {"selectors": live})]
    return []


def sends_mail(domain: str) -> bool:
    mx = [str(r.exchange).rstrip(".") for r in resolve(domain, "MX")]
    return bool(mx) and mx != [""]  # a null MX ("0 .") declares that the domain sends no mail


def dkim_records(domain: str) -> dict[str, str]:
    def one(sel):
        try:
            return sel, " ".join(r for r in txt_records(f"{sel}._domainkey.{domain}") if "p=" in r.replace(" ", ""))
        except LookupFailed:
            return sel, ""
    with ThreadPoolExecutor(max_workers=8) as pool:
        return {sel: rec for sel, rec in pool.map(one, DKIM_SELECTORS) if rec}


def collect(domain: str) -> tuple[list[RawFinding], int]:
    """Returns findings and 1 if the factor was assessed, 0 if DNS was unreliable."""
    if not zone_is_reachable(domain):
        return [], 0
    try:
        findings = evaluate_spf(domain, txt_records(domain))
        findings += evaluate_dmarc(domain, txt_records(f"_dmarc.{domain}"))
        findings += evaluate_mta_sts(domain, txt_records(f"_mta-sts.{domain}"))
        if sends_mail(domain):
            findings += evaluate_dkim(domain, dkim_records(domain))
    except LookupFailed:
        return [], 0
    return findings, 1
