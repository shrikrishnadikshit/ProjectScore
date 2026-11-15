"""Web security collector (risk factors 6 and 7): one GET per host, headers only."""

from concurrent.futures import ThreadPoolExecutor

import httpx

from . import RawFinding, software

USER_AGENT = "ProjectScore-Scanner/0.1 (+passive security rating; opt-out page to follow)"

HEADER_CHECKS = [
    ("content-security-policy", "csp_missing", "No Content-Security-Policy header", "low"),
    ("x-frame-options", "xfo_missing", "No clickjacking protection (X-Frame-Options / frame-ancestors)", "low"),
    ("x-content-type-options", "xcto_missing", "No X-Content-Type-Options header", "info"),
]


def evaluate_headers(host: str, headers: dict[str, str], set_cookies: list[str]) -> list[RawFinding]:
    h = {k.lower(): v for k, v in headers.items()}
    findings = []
    if "strict-transport-security" not in h:
        findings.append(RawFinding("tls", "hsts_missing", "No HSTS header", "low", host))
    for name, code, title, severity in HEADER_CHECKS:
        if name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
            continue
        if name not in h:
            findings.append(RawFinding("web_security", code, title, severity, host))
    for cookie in set_cookies:
        lower = cookie.lower()
        if "secure" not in lower or "httponly" not in lower:
            findings.append(RawFinding("web_security", "cookie_flags", "Cookie without Secure/HttpOnly flags",
                                       "low", host, {"cookie": cookie.split("=", 1)[0]}))
            break
    return findings


def _fetch(client: httpx.Client, host: str):
    try:
        return host, client.get(f"https://{host}/")
    except httpx.HTTPError:
        return host, None


def collect(hosts: list[str], workers: int = 5) -> tuple[list[RawFinding], int, int]:
    """Returns findings, hosts assessed for web security, and hosts with identifiable software versions."""
    findings, assessed, versioned = [], 0, 0
    with httpx.Client(timeout=8.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda h: _fetch(client, h), hosts))
    for host, resp in results:
        if resp is None:
            continue
        assessed += 1
        headers = dict(resp.headers)
        findings += evaluate_headers(host, headers, resp.headers.get_list("set-cookie"))
        sw_findings, has_versions = software.evaluate(host, headers)
        findings += sw_findings
        versioned += has_versions
    return findings, assessed, versioned
