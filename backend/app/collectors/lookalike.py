"""Look-alike domains (BRS factor "brand"): registered typo and homoglyph variants of a company's domain.

Look-alike domains are used for phishing and invoice fraud against a company's staff, customers and
suppliers. We generate common variants (missing, doubled, swapped or neighbouring letters, look-alike
characters, hyphens and other top-level domains) and check passively in DNS which are registered. Ones
that share the company's own nameservers are treated as defensive registrations and ignored.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from . import RawFinding

# Severity is deliberately low: many look-alikes are parked by registrars or owned by the company itself
# under other nameservers, and we cannot tell those apart passively. They are listed for review.
from .dns_util import LookupFailed, resolve

FACTOR = "brand"
MAX_CANDIDATES = 400
MAX_FINDINGS = 20

KEYBOARD = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl",
    "p": "o", "a": "qsz", "s": "awdz", "d": "sefx", "f": "drgc", "g": "fthv", "h": "gyjb", "j": "hukn",
    "k": "jilm", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm",
    "m": "njk",
}
HOMOGLYPHS = {"o": ["0"], "0": ["o"], "l": ["1", "i"], "i": ["1", "l"], "1": ["l", "i"], "m": ["rn"],
              "w": ["vv"], "e": ["3"], "a": ["4"], "s": ["5"], "g": ["q"], "b": ["d"], "d": ["b", "cl"]}
TLDS = ["com", "net", "org", "in", "co.in", "co", "io", "info", "biz", "online", "site", "xyz", "app"]


def split_domain(domain: str) -> tuple[str, str]:
    """('acme', 'co.in') for acme.co.in; ('acme', 'com') for acme.com. Subdomains are not expected."""
    parts = domain.lower().split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "ac", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[:-2]), ".".join(parts[-2:])
    return ".".join(parts[:-1]), parts[-1]


def candidates(domain: str) -> list[str]:
    name, tld = split_domain(domain)
    if "." in name or len(name) < 3:
        return []
    variants: set[str] = set()
    for i, ch in enumerate(name):
        variants.add(name[:i] + name[i + 1:])                       # omission
        variants.add(name[:i] + ch + ch + name[i + 1:])             # repetition
        if i < len(name) - 1:
            variants.add(name[:i] + name[i + 1] + ch + name[i + 2:])  # transposition
            variants.add(name[:i + 1] + "-" + name[i + 1:])         # hyphenation
        for k in KEYBOARD.get(ch, ""):
            variants.add(name[:i] + k + name[i + 1:])               # neighbouring key
        for g in HOMOGLYPHS.get(ch, []):
            variants.add(name[:i] + g + name[i + 1:])               # look-alike characters
    variants |= {name + s for s in ("-login", "-secure", "-support", "-pay", "-india", "online", "app")}
    variants.discard(name)
    out = [f"{v}.{tld}" for v in sorted(variants) if v and not v.startswith("-") and not v.endswith("-")]
    out += [f"{name}.{t}" for t in TLDS if t != tld]
    return [d for d in dict.fromkeys(out) if d != domain][:MAX_CANDIDATES]


def _ns(domain: str) -> set[str]:
    try:
        return {str(r.target).rstrip(".").lower() for r in resolve(domain, "NS")}
    except LookupFailed:
        return set()


def probe(domain: str) -> dict | None:
    """Registered-and-live information about a candidate, or None if it does not resolve."""
    try:
        ns = {str(r.target).rstrip(".").lower() for r in resolve(domain, "NS")}
        if not ns:
            return None
        mx = [str(r.exchange).rstrip(".") for r in resolve(domain, "MX")]
        a = [str(r) for r in resolve(domain, "A")]
    except LookupFailed:
        return None
    return {"ns": sorted(ns), "mx": [m for m in mx if m], "a": a}


def evaluate(domain: str, registered: dict[str, dict], own_ns: set[str]) -> list[RawFinding]:
    findings = []
    for d, info in sorted(registered.items(), key=lambda kv: (not kv[1]["mx"], kv[0])):
        if own_ns and own_ns & set(info["ns"]):
            continue  # same nameservers as the company: most likely its own defensive registration
        if info["mx"]:
            findings.append(RawFinding(FACTOR, "lookalike_domain_mail", f"Look-alike domain {d} can receive and send email",
                                       "low", d, {"lookalike_of": domain, **info}, 0.5))
        elif info["a"]:
            findings.append(RawFinding(FACTOR, "lookalike_domain_web", f"Look-alike domain {d} is registered and hosts a website",
                                       "info", d, {"lookalike_of": domain, **info}, 0.5))
        if len(findings) >= MAX_FINDINGS:
            break
    return findings


def collect(domain: str, probe_fn=probe, workers: int = 16) -> tuple[list[RawFinding], int]:
    """Returns findings and coverage for the brand factor (0 if DNS for the company itself failed)."""
    own_ns = _ns(domain)
    if not own_ns:
        return [], 0
    cands = candidates(domain)
    if not cands:
        return [], 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = dict(zip(cands, pool.map(probe_fn, cands)))
    registered = {d: info for d, info in results.items() if info}
    findings = evaluate(domain, registered, own_ns)
    return findings, max(1, len(findings))
