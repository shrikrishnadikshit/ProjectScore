"""Outdated JavaScript libraries referenced by a web page (risk factor 7, BRS web application security).

Passive: reads the script URLs in the HTML page the web collector already downloaded. Versions are
taken from file names and CDN paths, so libraries bundled into the site's own code are not seen.
"""

import re

from . import RawFinding

FACTOR = "web_security"

_SCRIPT_SRC = re.compile(r"<script[^>]+src\s*=\s*[\"']([^\"']+)[\"']", re.I)
_VERSION = r"v?(\d+\.\d+\.\d+)"
LIBRARIES = [
    # name, pattern (version group), rule(version) -> (code, title, severity) or None
    ("jQuery UI", re.compile(r"jquery[-.]?ui[^/]*?[-@/.]" + _VERSION, re.I),
     lambda v: ("jqueryui_vulnerable", "Outdated jQuery UI with known XSS vulnerabilities (before 1.13.0)", "medium")
     if v < (1, 13, 0) else None),
    ("jQuery", re.compile(r"jquery(?![-.]?ui)(?:\.min)?[-@/.]" + _VERSION, re.I),
     lambda v: ("jquery_vulnerable_old", "Very old jQuery with multiple known vulnerabilities (before 1.9)", "high")
     if v < (1, 9, 0) else ("jquery_vulnerable", "Outdated jQuery with known XSS vulnerabilities (before 3.5.0)", "medium")
     if v < (3, 5, 0) else None),
    ("AngularJS", re.compile(r"angular(?:js|\.js)?[-@/.](1\.\d+\.\d+)", re.I),
     lambda v: ("angularjs_eol", "AngularJS 1.x, end of life since January 2022", "medium")),
    ("Bootstrap", re.compile(r"bootstrap[-@/.]" + _VERSION, re.I),
     lambda v: ("bootstrap_vulnerable", "Outdated Bootstrap with known XSS vulnerabilities", "low")
     if v < (3, 4, 1) or (4, 0, 0) <= v < (4, 3, 1) else None),
    ("Lodash", re.compile(r"lodash[-@/.]" + _VERSION, re.I),
     lambda v: ("lodash_vulnerable", "Outdated Lodash with known prototype-pollution vulnerabilities", "medium")
     if v < (4, 17, 21) else None),
    ("Moment.js", re.compile(r"moment[-@/.]" + _VERSION, re.I),
     lambda v: ("moment_vulnerable", "Outdated Moment.js with known vulnerabilities (before 2.29.4)", "low")
     if v < (2, 29, 4) else None),
    ("Handlebars", re.compile(r"handlebars[-@/.]" + _VERSION, re.I),
     lambda v: ("handlebars_vulnerable", "Outdated Handlebars with known code-execution vulnerabilities", "medium")
     if v < (4, 7, 7) else None),
    ("Vue 2", re.compile(r"vue[-@/.](2\.\d+\.\d+)", re.I),
     lambda v: ("vue2_eol", "Vue 2, end of life since December 2023", "low")),
]


def _v(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in text.split("."))


def detect(html: str) -> list[tuple[str, str]]:
    """Returns (library, version) pairs found in script URLs, de-duplicated."""
    found: dict[str, str] = {}
    for src in _SCRIPT_SRC.findall(html[:500_000]):
        for name, pattern, _ in LIBRARIES:
            m = pattern.search(src)
            if m and name not in found:
                found[name] = m.group(1)
                break
    return list(found.items())


def evaluate(host: str, html: str) -> list[RawFinding]:
    rules = {name: rule for name, _, rule in LIBRARIES}
    findings = []
    for name, version in detect(html):
        result = rules[name](_v(version))
        if result:
            code, title, severity = result
            findings.append(RawFinding(FACTOR, code, title, severity, host,
                                       {"library": name, "version": version}, 0.9))
    return findings
