"""Vulnerability & patching factor (risk factor 2) from software versions that
web servers disclose in their headers. Passive: uses the response already fetched
by the web collector.

This is a curated first version. Version-to-CVE matching against NVD/OSV and the
full CISA KEV and FIRST EPSS feeds comes next.
"""

import re

from . import RawFinding

FACTOR = "vulnerability"

_PRODUCT_RE = re.compile(r"(apache|nginx|microsoft-iis|php|openssl|lighttpd)/(\d+(?:\.\d+){0,2})", re.I)

# (product, version predicate, code, title, severity, extra evidence)
RULES = [
    ("apache", lambda v: v[:3] in ((2, 4, 49), (2, 4, 50)), "apache_path_traversal_kev",
     "Apache HTTP Server version with actively exploited path traversal (CVE-2021-41773 / CVE-2021-42013)",
     "critical", {"kev": True, "cves": ["CVE-2021-41773", "CVE-2021-42013"]}),
    ("apache", lambda v: v[:2] < (2, 4), "apache_eol", "End-of-life Apache HTTP Server (2.2 or older)", "high", {}),
    ("apache", lambda v: len(v) >= 3 and v[:2] == (2, 4) and v[2] < 60, "apache_outdated",
     "Outdated Apache HTTP Server 2.4 release with published vulnerabilities", "medium", {}),
    ("openssl", lambda v: (1, 0, 1) <= v[:3] < (1, 0, 2), "openssl_heartbleed_risk",
     "OpenSSL 1.0.1 branch disclosed (Heartbleed, CVE-2014-0160, affects 1.0.1 to 1.0.1f)",
     "high", {"cves": ["CVE-2014-0160"]}),
    ("openssl", lambda v: v[:2] < (3, 0), "openssl_eol", "End-of-life OpenSSL (1.1.1 or older)", "medium", {}),
    ("microsoft-iis", lambda v: v[:1] < (10,), "iis_eol",
     "Microsoft IIS version from an end-of-life Windows Server release", "high", {}),
    ("php", lambda v: v[:1] < (8,), "php_eol_old", "Very old, end-of-life PHP (7.x or older)", "high", {}),
    ("php", lambda v: v[:1] == (8,) and v[:2] < (8, 2), "php_eol", "End-of-life PHP (8.0 or 8.1)", "medium", {}),
    ("nginx", lambda v: v[:2] < (1, 20), "nginx_outdated", "Outdated nginx release with published vulnerabilities",
     "medium", {}),
    ("lighttpd", lambda v: v[:2] < (1, 4), "lighttpd_eol", "End-of-life lighttpd", "medium", {}),
]


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in text.split("."))


def software_in(headers: dict[str, str]) -> list[tuple[str, str]]:
    h = {k.lower(): v for k, v in headers.items()}
    banner = " ".join(h.get(k, "") for k in ("server", "x-powered-by"))
    return [(p.lower(), v) for p, v in _PRODUCT_RE.findall(banner)]


def evaluate(host: str, headers: dict[str, str]) -> tuple[list[RawFinding], bool]:
    """Returns findings and whether any versioned software was identified on this host."""
    found = software_in(headers)
    findings = []
    for product, version_text in found:
        version = _version(version_text)
        for rule_product, predicate, code, title, severity, extra in RULES:
            if rule_product == product and predicate(version):
                findings.append(RawFinding(FACTOR, code, title, severity, host,
                                           {"software": f"{product}/{version_text}", **extra}, 0.8))
                break  # first (most severe) matching rule per product
    return findings, bool(found)
