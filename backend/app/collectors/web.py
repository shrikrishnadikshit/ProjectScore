"""Web security collector (risk factors 6 and 7): one GET per host, headers only."""

import httpx

from . import RawFinding

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


def collect(hosts: list[str]) -> tuple[list[RawFinding], int]:
    findings, assessed = [], 0
    with httpx.Client(timeout=8.0, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
        for host in hosts:
            try:
                resp = client.get(f"https://{host}/")
            except httpx.HTTPError:
                continue
            assessed += 1
            findings += evaluate_headers(host, dict(resp.headers), resp.headers.get_list("set-cookie"))
    return findings, assessed
