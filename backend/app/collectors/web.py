"""Web security collector (risk factors 6 and 7): one GET per host, headers only."""

from concurrent.futures import ThreadPoolExecutor

import httpx

from . import RawFinding, jslibs, software

import os

# Identifies the scanner and links to the public page that explains it and offers an opt-out.
SCANNER_INFO_URL = os.getenv("SCANNER_INFO_URL", "https://projectscore.onrender.com/scanner")
USER_AGENT = f"ProjectScore-Scanner/1.0 (+{SCANNER_INFO_URL}; passive security rating)"

# Page-level protections only matter for HTML documents, not APIs, images or downloads.
HTML_ONLY = {"content-security-policy", "x-frame-options"}
# HttpOnly matters for cookies that carry a session or credential; analytics cookies set for
# JavaScript to read are expected not to have it.
SESSION_COOKIE_HINTS = ("sess", "sid", "auth", "token", "login", "jwt", "csrf", "remember")

HEADER_CHECKS = [
    ("content-security-policy", "csp_missing", "No Content-Security-Policy header", "low"),
    ("x-frame-options", "xfo_missing", "No clickjacking protection (X-Frame-Options / frame-ancestors)", "low"),
    ("x-content-type-options", "xcto_missing", "No X-Content-Type-Options header", "info"),
]


def _cookie_attrs(cookie: str) -> tuple[str, set[str]]:
    parts = [p.strip() for p in cookie.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
    return name, attrs


def evaluate_headers(host: str, headers: dict[str, str], set_cookies: list[str]) -> list[RawFinding]:
    h = {k.lower(): v for k, v in headers.items()}
    is_html = "text/html" in h.get("content-type", "").lower()
    findings = []
    if "strict-transport-security" not in h:
        findings.append(RawFinding("tls", "hsts_missing", "No HSTS header", "low", host))
    for name, code, title, severity in HEADER_CHECKS:
        if name in HTML_ONLY and not is_html:
            continue
        if name == "x-frame-options" and "frame-ancestors" in h.get("content-security-policy", ""):
            continue
        if name not in h:
            findings.append(RawFinding("web_security", code, title, severity, host))
    insecure, scriptable = [], []
    for cookie in set_cookies:
        name, attrs = _cookie_attrs(cookie)
        if "secure" not in attrs:
            insecure.append(name)
        elif "httponly" not in attrs and any(hint in name.lower() for hint in SESSION_COOKIE_HINTS):
            scriptable.append(name)
    if insecure:
        findings.append(RawFinding("web_security", "cookie_not_secure", "Cookie sent without the Secure flag",
                                   "low", host, {"cookies": insecure[:5]}))
    if scriptable:
        findings.append(RawFinding("web_security", "session_cookie_not_httponly",
                                   "Session cookie readable by scripts (no HttpOnly flag)", "medium", host,
                                   {"cookies": scriptable[:5]}))
    return findings


def _fetch(client: httpx.Client, host: str):
    try:
        return host, client.get(f"https://{host}/")
    except httpx.HTTPError:
        return host, None


def _in_scope(host: str, domain: str | None) -> bool:
    return domain is None or host == domain or host.endswith("." + domain)


def collect(hosts: list[str], workers: int = 5, domain: str | None = None) -> tuple[list[RawFinding], int, int]:
    """Returns findings, hosts assessed for web security, and hosts with identifiable software versions.

    Redirects are followed, and the page that is finally served is evaluated once and attributed to the
    host that served it. Pages served from outside the entity's domain are not attributed to it.
    """
    findings, assessed, versioned = [], 0, 0
    with httpx.Client(timeout=8.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda h: _fetch(client, h), hosts))
    evaluated = set()
    for _, resp in results:
        if resp is None:
            continue
        host = (resp.url.host or "").lower()
        if resp.url.scheme != "https" or not _in_scope(host, domain) or host in evaluated:
            continue
        evaluated.add(host)
        assessed += 1
        headers = dict(resp.headers)
        findings += evaluate_headers(host, headers, resp.headers.get_list("set-cookie"))
        if "text/html" in headers.get("content-type", "").lower():
            findings += jslibs.evaluate(host, resp.text)
        sw_findings, has_versions = software.evaluate(host, headers)
        findings += sw_findings
        versioned += has_versions
    return findings, assessed, versioned
