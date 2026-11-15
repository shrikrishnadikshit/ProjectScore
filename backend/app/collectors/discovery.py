"""Passive subdomain discovery from Certificate Transparency logs (crt.sh).

Only names that sit under the entity's own domain are kept, so attribution
confidence is high. Nothing is sent to the discovered hosts here.
"""

import logging
import re

import httpx

from .dns_util import LookupFailed, resolve
from .web import USER_AGENT

logger = logging.getLogger("projectscore.discovery")

CRT_SH_URL = "https://crt.sh/"
MAX_HOSTS = 25
_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def parse_ct_names(domain: str, records: list[dict]) -> set[str]:
    names = set()
    for rec in records:
        for raw in str(rec.get("name_value", "")).split("\n"):
            name = raw.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name != domain and not name.endswith("." + domain):
                continue
            if all(_LABEL_RE.match(label) for label in name.split(".")):
                names.add(name)
    return names


def fetch_ct_names(domain: str) -> set[str]:
    try:
        resp = httpx.get(CRT_SH_URL, params={"q": f"%.{domain}", "output": "json"},
                         headers={"User-Agent": USER_AGENT}, timeout=45.0)
        resp.raise_for_status()
        return parse_ct_names(domain, resp.json())
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("CT lookup failed for %s: %s", domain, exc)
        return set()


def prioritise(domain: str, names: set[str], limit: int = MAX_HOSTS) -> list[str]:
    """Apex and www first, then shallower names (usually the main services), then alphabetical."""
    first = [h for h in (domain, f"www.{domain}") if h in names]
    rest = sorted(names - set(first), key=lambda h: (h.count("."), h))
    return (first + rest)[:limit]


def is_live(host: str) -> bool:
    try:
        return bool(resolve(host, "A") or resolve(host, "AAAA") or resolve(host, "CNAME"))
    except LookupFailed:
        return False


def discover_hosts(domain: str) -> list[str]:
    """Returns live subdomains found in CT logs, excluding the apex and www (always scanned)."""
    names = fetch_ct_names(domain) - {domain, f"www.{domain}"}
    candidates = prioritise(domain, names, limit=MAX_HOSTS * 2)
    return [h for h in candidates if is_live(h)][:MAX_HOSTS - 2]
