"""IP addresses, registered IP ranges and exposed network services (risk factors 2 and 3).

Passive only: the platform never connects to these IPs itself. Ownership comes from public
registry (RDAP) records; open ports and vulnerable software come from existing internet-wide
scan data (Shodan InternetDB by default, or the Shodan API with a key).

Source licensing must be validated before commercial use (BRS Section 23): InternetDB's free
data is offered for non-commercial use; production use needs a commercial data licence.
"""

import ipaddress
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import RawFinding, kev
from .dns_util import LookupFailed, resolve
from .web import USER_AGENT

logger = logging.getLogger("projectscore.network")

RDAP_URL = "https://rdap.org/ip/{ip}"
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
SHODAN_URL = "https://api.shodan.io/shodan/host/{ip}"
MAX_IPS = int(os.getenv("MAX_IPS_PER_ENTITY", "64"))
MAX_BLOCK_PREFIX = 22  # only expand owned blocks of 1,024 addresses or fewer

# port: (code, title, severity)
RISKY_PORTS = {
    23: ("telnet_exposed", "Telnet exposed to the internet", "high"),
    21: ("ftp_exposed", "FTP exposed to the internet", "medium"),
    3389: ("rdp_exposed", "Remote Desktop (RDP) exposed to the internet", "high"),
    5900: ("vnc_exposed", "VNC remote access exposed to the internet", "high"),
    445: ("smb_exposed", "Windows file sharing (SMB) exposed to the internet", "critical"),
    139: ("netbios_exposed", "NetBIOS exposed to the internet", "high"),
    1433: ("db_exposed", "Database port exposed to the internet (SQL Server)", "high"),
    3306: ("db_exposed", "Database port exposed to the internet (MySQL)", "high"),
    5432: ("db_exposed", "Database port exposed to the internet (PostgreSQL)", "high"),
    1521: ("db_exposed", "Database port exposed to the internet (Oracle)", "high"),
    27017: ("db_exposed", "Database port exposed to the internet (MongoDB)", "high"),
    6379: ("db_exposed", "Database port exposed to the internet (Redis)", "high"),
    9200: ("db_exposed", "Search database exposed to the internet (Elasticsearch)", "high"),
    11211: ("db_exposed", "Cache service exposed to the internet (Memcached)", "high"),
    161: ("snmp_exposed", "SNMP exposed to the internet", "medium"),
    502: ("ics_exposed", "Industrial control protocol exposed (Modbus)", "critical"),
    102: ("ics_exposed", "Industrial control protocol exposed (Siemens S7)", "critical"),
    20000: ("ics_exposed", "Industrial control protocol exposed (DNP3)", "critical"),
    47808: ("ics_exposed", "Building automation protocol exposed (BACnet)", "critical"),
    2375: ("docker_api_exposed", "Docker API exposed to the internet", "critical"),
    6443: ("k8s_api_exposed", "Kubernetes API exposed to the internet", "medium"),
}
GENERIC_WORDS = {"inc", "ltd", "llc", "plc", "corp", "corporation", "company", "group", "limited", "the",
                 "holdings", "services", "technologies", "technology", "solutions", "international", "global",
                 "pvt", "private", "gmbh", "network", "networks", "systems", "data", "cloud", "com", "net", "org"}


# ---------- Discovery ----------

def resolve_ips(hosts: list[str]) -> dict[str, list[str]]:
    ips: dict[str, list[str]] = {}
    for host in hosts:
        try:
            for rec in resolve(host, "A"):
                ips.setdefault(str(rec.address) if hasattr(rec, "address") else str(rec), []).append(host)
        except LookupFailed:
            continue
    return {ip: hs for ip, hs in ips.items() if ipaddress.ip_address(ip).is_global}


def parse_rdap(data: dict) -> dict:
    names = [data.get("name") or ""]
    for ent in data.get("entities", []) or []:
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn":
                names.append(str(item[3]))
    cidrs = [f"{c['v4prefix']}/{c['length']}" for c in data.get("cidr0_cidrs", []) or [] if c.get("v4prefix")]
    return {"handle": data.get("handle"), "names": [n for n in names if n], "cidrs": cidrs}


def _tokens(text: str) -> set[str]:
    return {t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) >= 4 and t not in GENERIC_WORDS}


def is_owned(rdap: dict, entity_name: str, domain: str) -> bool:
    """A block counts as the company's own only if the registry names the company itself,
    not a hosting provider. Matches the domain's main label or a distinctive word of the name."""
    keys = _tokens(entity_name) | _tokens(domain.split(".")[0])
    registered = set()
    for n in rdap["names"]:
        registered |= _tokens(n)
    return bool(keys & registered)


def rdap_lookup(client: httpx.Client, ip: str) -> dict | None:
    try:
        resp = client.get(RDAP_URL.format(ip=ip), follow_redirects=True)
        resp.raise_for_status()
        return parse_rdap(resp.json())
    except (httpx.HTTPError, ValueError) as exc:
        logger.info("RDAP lookup failed for %s: %s", ip, exc)
        return None


# ---------- Exposure ----------

def _exposure_source() -> str:
    if os.getenv("SHODAN_API_KEY"):
        return "shodan"
    return os.getenv("EXPOSURE_SOURCE", "internetdb")


def exposure_lookup(client: httpx.Client, ip: str) -> dict | None:
    """Returns {"ports": [...], "vulns": [...], "tags": [...]} or None if the source failed.
    An IP the source has never seen with open ports returns empty lists."""
    source = _exposure_source()
    try:
        if source == "shodan":
            resp = client.get(SHODAN_URL.format(ip=ip), params={"key": os.environ["SHODAN_API_KEY"], "minify": "true"})
            if resp.status_code == 404:
                return {"ports": [], "vulns": [], "tags": []}
            resp.raise_for_status()
            d = resp.json()
            return {"ports": d.get("ports", []), "vulns": list((d.get("vulns") or {})), "tags": d.get("tags", [])}
        if source == "internetdb":
            resp = client.get(INTERNETDB_URL.format(ip=ip))
            if resp.status_code == 404:
                return {"ports": [], "vulns": [], "tags": []}
            resp.raise_for_status()
            d = resp.json()
            return {"ports": d.get("ports", []), "vulns": d.get("vulns", []), "tags": d.get("tags", [])}
    except (httpx.HTTPError, ValueError) as exc:
        logger.info("exposure lookup failed for %s: %s", ip, exc)
    return None


def evaluate_exposure(ip: str, data: dict, kev_ids: frozenset[str]) -> list[RawFinding]:
    findings = []
    ports = sorted(set(data.get("ports", [])))
    for port in ports:
        if port in RISKY_PORTS:
            code, title, severity = RISKY_PORTS[port]
            findings.append(RawFinding("network_exposure", f"{code}_{port}", title, severity, ip,
                                       {"port": port, "source": _exposure_source()}, 0.9))
    vulns = sorted({v.upper() for v in data.get("vulns", [])})
    exploited = [v for v in vulns if v in kev_ids]
    if exploited:
        findings.append(RawFinding("vulnerability", "kev_exposed", "Exposed software affected by actively "
                                   "exploited vulnerabilities (CISA KEV)", "critical", ip,
                                   {"kev": True, "cves": exploited[:20]}, 0.7))
    others = [v for v in vulns if v not in kev_ids]
    if others:
        findings.append(RawFinding("vulnerability", "known_cves", f"Exposed software with {len(others)} published "
                                   "vulnerabilities", "medium", ip, {"cves": others[:20]}, 0.5))
    return findings


# ---------- Collector ----------

def collect(hosts: list[str], entity_name: str, domain: str) -> tuple[list[RawFinding], dict[str, int], list[tuple[str, str]]]:
    """Returns findings, coverage per factor, and discovered assets as (type, value)."""
    if _exposure_source() == "off":
        return [], {}, []
    resolved = resolve_ips(hosts)
    if not resolved:
        return [], {}, []
    assets: list[tuple[str, str]] = []
    targets: list[str] = list(resolved)[:MAX_IPS]
    with httpx.Client(timeout=15.0, headers={"User-Agent": USER_AGENT}) as client:
        seen_blocks = set()
        with ThreadPoolExecutor(max_workers=4) as pool:
            rdaps = dict(zip(targets, pool.map(lambda ip: rdap_lookup(client, ip), targets)))
        for ip, rdap in rdaps.items():
            if not rdap or not is_owned(rdap, entity_name, domain):
                continue
            for cidr in rdap["cidrs"]:
                if cidr in seen_blocks:
                    continue
                seen_blocks.add(cidr)
                net = ipaddress.ip_network(cidr, strict=False)
                assets.append(("netblock", str(net)))
                if net.prefixlen >= MAX_BLOCK_PREFIX:
                    for addr in net.hosts():
                        if len(targets) >= MAX_IPS:
                            break
                        if str(addr) not in targets:
                            targets.append(str(addr))
        with ThreadPoolExecutor(max_workers=4) as pool:
            exposures = dict(zip(targets, pool.map(lambda ip: exposure_lookup(client, ip), targets)))

    kev_ids = kev.kev_ids()
    findings, assessed, with_software = [], 0, 0
    for ip, data in exposures.items():
        if data is None:
            continue
        tags = {t.lower() for t in data.get("tags", [])}
        if "cdn" in tags and ip in resolved:
            continue  # shared CDN edge: open ports belong to the CDN provider, not the company
        assessed += 1
        if ip in resolved or data.get("ports"):
            assets.append(("ip", ip))
        with_software += bool(data.get("vulns"))
        findings += evaluate_exposure(ip, data, kev_ids)
    return findings, {"network_exposure": assessed, "vulnerability": with_software}, assets
