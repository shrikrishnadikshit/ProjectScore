"""Fake websites copying a company (BRS factor "brand").

Look-alike domains that host a website are opened once, like any visitor would, and checked for signs of
impersonation: the company's name or page title, a password or payment form, or a redirect to the real
site (often a sign of a phishing kit hiding from scanners or of a defensive registration). Only the home
page is fetched; nothing is submitted.
"""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import RawFinding, netsafe
from .web import USER_AGENT

FACTOR = "brand"
MAX_SITES = 20
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_PASSWORD = re.compile(r"<input[^>]+type=[\"']?password", re.I)
_PAYMENT = re.compile(r"(card[\s_-]?number|cvv|cvc|expiry|upi[\s_-]?id|net[\s_-]?banking)", re.I)
_PARKED = re.compile(r"(domain (is )?for sale|buy this domain|parked (free|domain)|sedo|dan\.com|afternic|godaddy\.com/forsale|"
                     r"this domain may be for sale|hugedomains)", re.I)


def enabled() -> bool:
    return os.environ.get("IMPERSONATION_CHECK", "on").lower() != "off"


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]{3,}", (text or "").lower())}


def fetch(host: str, client: httpx.Client) -> dict | None:
    for scheme in ("https", "http"):
        try:
            r = client.get(f"{scheme}://{host}/")
        except httpx.HTTPError:
            continue
        html = r.text[:300_000] if "html" in r.headers.get("content-type", "") else ""
        m = _TITLE.search(html)
        return {"status": r.status_code, "final_host": (r.url.host or "").lower(), "html": html,
                "title": re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""}
    return None


def assess(host: str, page: dict, domain: str, name: str, home_title: str) -> dict | None:
    """What a fetched look-alike page shows, or None when it is harmless (parked, empty, error)."""
    final = page["final_host"]
    if final == domain or final.endswith("." + domain):
        return {"kind": "redirects_to_real", "detail": f"redirects to {final}"}
    html, title = page["html"], page["title"]
    if page["status"] >= 400 or not html or _PARKED.search(html[:50_000]):
        return None
    brand = {w for w in _words(name) if w not in {"inc", "ltd", "llc", "limited", "the", "corp", "group", "pvt", "private"}}
    brand |= {domain.split(".")[0].lower()}
    text_words = _words(title + " " + html[:100_000])
    mentions = bool(brand & text_words)
    home = _words(home_title) - {"home", "the", "and", "welcome", "official", "site", "website"}
    copies_title = bool(home) and len(home & _words(title)) >= max(2, int(len(home) * 0.6))
    password, payment = bool(_PASSWORD.search(html)), bool(_PAYMENT.search(html))
    if (mentions or copies_title) and (password or payment):
        return {"kind": "phishing_like", "detail": "uses the company's name and asks for a " + ("password" if password else "payment details")}
    if copies_title:
        return {"kind": "copies_site", "detail": f"copies the company's page title ({title[:80]})"}
    if mentions:
        return {"kind": "uses_brand", "detail": f"mentions the company's name ({title[:80] or 'no title'})"}
    return None


SEVERITY = {"phishing_like": "high", "copies_site": "medium", "uses_brand": "low", "redirects_to_real": "info"}
TITLES = {"phishing_like": "Possible phishing site imitating the company: {d}",
          "copies_site": "Website on look-alike domain {d} copies the company's site",
          "uses_brand": "Website on look-alike domain {d} uses the company's name",
          "redirects_to_real": "Look-alike domain {d} redirects to the company's real site"}


def check(domain: str, name: str, lookalikes: list[RawFinding], fetch_fn=None) -> list[RawFinding]:
    if not (enabled() or fetch_fn):
        return []
    hosts = [f.asset_value for f in lookalikes if f.code.startswith("lookalike_domain_")][:MAX_SITES]
    if not hosts:
        return []
    with httpx.Client(timeout=8.0, follow_redirects=True, headers={"User-Agent": USER_AGENT},
                      event_hooks={"request": [netsafe.block_private_redirects]}) as client:
        get = fetch_fn or (lambda h: fetch(h, client))
        home = get(domain) or {"title": ""}
        hosts = hosts if fetch_fn else netsafe.public_hosts(hosts)
        with ThreadPoolExecutor(max_workers=8) as pool:
            pages = dict(zip(hosts, pool.map(get, hosts)))
    out = []
    for h, page in pages.items():
        verdict = page and assess(h, page, domain, name, home.get("title", ""))
        if not verdict:
            continue
        kind = verdict["kind"]
        out.append(RawFinding(FACTOR, f"impersonation_{kind}", TITLES[kind].format(d=h), SEVERITY[kind], h,
                              {"lookalike_of": domain, "page_title": page.get("title"), "detail": verdict["detail"],
                               "kind": kind}, 0.7 if kind == "phishing_like" else 0.5))
    return out
