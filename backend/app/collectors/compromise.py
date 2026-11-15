"""Compromise and malicious-activity signals (BRS factor "compromise", 20% weight).

Matches a company's hostnames and IP addresses against free public threat feeds:

- abuse.ch Feodo Tracker: botnet command-and-control servers (CC0).
- abuse.ch URLhaus: URLs currently serving malware (CC0).
- Spamhaus DROP: netblocks hijacked or run by criminals (free to use).
- blocklist.de: IPs reported for attacking other systems in the last 48 hours (free to use).

All of this is passive: nothing is sent to the company's systems. Feeds are cached in memory for six
hours. If no feed can be loaded, the factor is "not assessed" rather than counted as clean.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import threading
import time
from urllib.parse import urlsplit

import httpx

from . import RawFinding

logger = logging.getLogger("projectscore.compromise")

FEEDS = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
    "drop": "https://www.spamhaus.org/drop/drop_v4.json",
    "blocklist_de": "https://lists.blocklist.de/lists/all.txt",
}
_TTL = 6 * 3600
# A host with this many malware URLs is a platform abused by its users (file sharing, code hosting),
# which says little about the company's own security, so it is reported at low severity.
SHARED_PLATFORM_URLS = 10

_lock = threading.Lock()
_cache: dict[str, tuple[float, object]] = {}


def parse_feodo(data) -> dict[str, str]:
    """IP -> malware family."""
    rows = data if isinstance(data, list) else []
    return {r["ip_address"]: r.get("malware") or "botnet" for r in rows if r.get("ip_address")}


def parse_urlhaus(text: str) -> dict[str, int]:
    """Host -> number of online malware URLs."""
    counts: dict[str, int] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = (urlsplit(line).hostname or "").lower().rstrip(".")
        if host:
            counts[host] = counts.get(host, 0) + 1
    return counts


def parse_drop(text: str) -> list[tuple[ipaddress.IPv4Network, str]]:
    """Spamhaus DROP is newline-delimited JSON with a trailing metadata line."""
    nets = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
            nets.append((ipaddress.ip_network(row["cidr"], strict=False), row.get("sblid", "")))
        except (ValueError, KeyError, TypeError):
            continue
    return nets


def parse_ip_list(text: str) -> frozenset[str]:
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            try:
                out.add(str(ipaddress.ip_address(line)))
            except ValueError:
                continue
    return frozenset(out)


_PARSERS = {
    "feodo": lambda r: parse_feodo(r.json()),
    "urlhaus": lambda r: parse_urlhaus(r.text),
    "drop": lambda r: parse_drop(r.text),
    "blocklist_de": lambda r: parse_ip_list(r.text),
}


def _feed(name: str):
    with _lock:
        loaded, value = _cache.get(name, (0.0, None))
        if time.time() - loaded < _TTL:
            return value
        try:
            resp = httpx.get(FEEDS[name], timeout=60.0, follow_redirects=True)
            resp.raise_for_status()
            value = _PARSERS[name](resp)
            logger.info("loaded %s feed (%d entries)", name, len(value))
            _cache[name] = (time.time(), value)
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning("could not load the %s feed: %s", name, exc)
            _cache[name] = (time.time() - _TTL + 900, value)  # keep any old copy, retry in 15 minutes
        return value


def load_feeds() -> dict:
    return {name: _feed(name) for name in FEEDS}


def _in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def evaluate(hosts: list[str], ips: dict[str, bool], domain: str, feeds: dict) -> list[RawFinding]:
    """`ips` maps each IP to True when it sits in a netblock registered to the company (higher
    attribution confidence) or False when it was only found by resolving one of its hostnames."""
    findings: list[RawFinding] = []
    feodo, urlhaus, drop, attackers = (feeds.get(k) for k in ("feodo", "urlhaus", "drop", "blocklist_de"))

    for ip, owned in sorted(ips.items()):
        conf = 1.0 if owned else 0.8
        if feodo and ip in feodo:
            findings.append(RawFinding(
                "compromise", "botnet_c2", f"IP address is a known botnet command-and-control server ({feodo[ip]})",
                "critical", ip, {"source": "abuse.ch Feodo Tracker", "malware": feodo[ip]}, conf))
        if drop:
            addr = ipaddress.ip_address(ip)
            hit = next((sbl for net, sbl in drop if addr.version == 4 and addr in net), None)
            if hit is not None:
                findings.append(RawFinding(
                    "compromise", "spamhaus_drop", "IP address is in a netblock on the Spamhaus DROP list",
                    "high", ip, {"source": "Spamhaus DROP", "sblid": hit}, conf))
        if attackers and ip in attackers:
            findings.append(RawFinding(
                "compromise", "attack_source", "IP address was reported attacking other systems in the last 48 hours",
                "medium", ip, {"source": "blocklist.de"}, conf * 0.8))

    if urlhaus:
        for host in sorted(set(hosts)):
            if not _in_scope(host, domain) or host not in urlhaus:
                continue
            n = urlhaus[host]
            if n >= SHARED_PLATFORM_URLS:
                findings.append(RawFinding(
                    "compromise", "malware_user_content", f"{n} malware files currently hosted by users of this service",
                    "low", host, {"source": "abuse.ch URLhaus", "urls": n}, 0.5))
            else:
                findings.append(RawFinding(
                    "compromise", "malware_hosting", "Website is currently serving malware",
                    "high", host, {"source": "abuse.ch URLhaus", "urls": n}, 0.9))
    return findings


def collect(hosts: list[str], ips: dict[str, bool], domain: str, feeds: dict | None = None
            ) -> tuple[list[RawFinding], int]:
    """Returns findings and how many assets were checked (0 when no feed could be loaded)."""
    if os.environ.get("COMPROMISE_FEEDS", "on").lower() == "off":
        return [], 0
    feeds = load_feeds() if feeds is None else feeds
    if not any(feeds.values()):
        return [], 0
    checked = (len(set(ips)) if any(feeds.get(k) for k in ("feodo", "drop", "blocklist_de")) else 0) + \
        (len(set(hosts)) if feeds.get("urlhaus") else 0)
    return evaluate(hosts, ips, domain, feeds), checked
