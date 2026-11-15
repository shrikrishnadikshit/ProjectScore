"""Where mentions and reviews come from.

Every source here is either free and open for commercial use, or switched off until the owner adds an
API key and accepts that provider's terms. See docs/REPUTATION.md for the licence notes on each one.

Each fetcher takes the brand's search terms and returns a list of plain dicts:
  source, kind, external_id, url, author, title, text, rating, published_at (aware datetime)
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote

import httpx

from ..collectors.web import SCANNER_INFO_URL

logger = logging.getLogger("projectscore.reputation")
USER_AGENT = f"ProjectScore-Reputation/1.0 (+{SCANNER_INFO_URL})"
TIMEOUT = 20.0

APPLE_ID_RE = re.compile(r"^\d{5,12}$")
PLACE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{10,200}$")
COUNTRY_RE = re.compile(r"^[a-z]{2}$")


def _on(name: str, default: str = "on") -> bool:
    return os.environ.get(name, default).lower() not in ("off", "false", "0", "no")


# key -> (label, kind, who it needs, attribution text)
SOURCES = {
    "news": ("News (GDELT)", "news", None, "News search by the GDELT Project (gdeltproject.org)"),
    "hackernews": ("Hacker News", "mention", None, "Hacker News search by Algolia"),
    "bluesky": ("Bluesky", "mention", None, "Posts from the Bluesky public API"),
    "reddit": ("Reddit", "mention", "REDDIT_CLIENT_ID and REDDIT_CLIENT_SECRET", "Posts from Reddit"),
    "apple": ("Apple App Store reviews", "review", None, "Customer reviews from the Apple App Store"),
}
DEFAULT_SOURCES = ["news", "hackernews", "bluesky", "apple"]


def source_available(key: str) -> bool:
    if key == "news":
        return _on("REPUTATION_NEWS")
    if key == "hackernews":
        return _on("REPUTATION_HACKERNEWS")
    if key == "bluesky":
        return _on("REPUTATION_BLUESKY")
    if key == "apple":
        return _on("REPUTATION_APPLE")
    if key == "reddit":
        return bool(os.environ.get("REDDIT_CLIENT_ID") and os.environ.get("REDDIT_CLIENT_SECRET"))
    return False


def google_available() -> bool:
    return bool(os.environ.get("GOOGLE_PLACES_API_KEY"))


def search_available() -> bool:
    return bool(os.environ.get("BRAVE_SEARCH_API_KEY"))


def _client() -> httpx.Client:
    return httpx.Client(timeout=TIMEOUT, headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                        follow_redirects=True)


def terms_query(terms: list[str], joiner: str = " OR ") -> str:
    quoted = [f'"{t}"' if " " in t else t for t in terms if t]
    return joiner.join(quoted)


def _clean(text: str | None, limit: int = 4000) -> str | None:
    if not text:
        return None
    text = re.sub(r"<[^>]+>", " ", text)
    text = (text.replace("&quot;", '"').replace("&#x27;", "'").replace("&#x2F;", "/").replace("&amp;", "&")
            .replace("&lt;", "<").replace("&gt;", ">"))
    return re.sub(r"\s+", " ", text).strip()[:limit] or None


def _dt(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    s = str(value).strip()
    for fmt in ("%Y%m%dT%H%M%SZ",):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    try:
        return parsedate_to_datetime(s)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------- GDELT news (free, open for any use)
_gdelt_lock = threading.Lock()
_gdelt_last = 0.0
GDELT_GAP_SECONDS = 6.0  # GDELT asks for at most one request every 5 seconds


def parse_gdelt(data: dict) -> list[dict]:
    out = []
    for a in (data or {}).get("articles") or []:
        url = a.get("url")
        if not url:
            continue
        out.append({"source": "news", "kind": "news", "external_id": url[:300], "url": url,
                    "author": a.get("domain"), "title": _clean(a.get("title"), 500), "text": None, "rating": None,
                    "published_at": _dt(a.get("seendate")), "language": a.get("language")})
    return out


def fetch_news(terms: list[str], since: datetime) -> list[dict]:
    global _gdelt_last
    hours = max(1, min(24 * 7, int((datetime.now(timezone.utc) - since).total_seconds() // 3600) + 1))
    query = terms_query(terms)
    if len(terms) > 1:
        query = f"({query})"
    params = {"query": query, "mode": "artlist", "format": "json", "maxrecords": "75", "sort": "datedesc",
              "timespan": f"{hours}h"}
    with _gdelt_lock:
        wait = GDELT_GAP_SECONDS - (time.monotonic() - _gdelt_last)
        if wait > 0:
            time.sleep(wait)
        try:
            with _client() as c:
                r = c.get("https://api.gdeltproject.org/api/v2/doc/doc", params=params)
        finally:
            _gdelt_last = time.monotonic()
    r.raise_for_status()
    if not r.text.strip().startswith("{"):  # GDELT answers errors as plain text with status 200
        raise ValueError(r.text.strip()[:200] or "empty response")
    return parse_gdelt(r.json())


# ---------------------------------------------------------------- Hacker News via Algolia (free)
def parse_hn(data: dict) -> list[dict]:
    out = []
    for h in (data or {}).get("hits") or []:
        oid = h.get("objectID")
        if not oid:
            continue
        is_comment = bool(h.get("comment_text"))
        out.append({"source": "hackernews", "kind": "mention", "external_id": str(oid),
                    "url": f"https://news.ycombinator.com/item?id={oid}", "author": h.get("author"),
                    "title": _clean(h.get("title") or (f"Comment on: {h.get('story_title')}" if h.get("story_title") else None), 500),
                    "text": _clean(h.get("comment_text") or h.get("story_text")) if is_comment or h.get("story_text") else None,
                    "rating": None, "published_at": _dt(h.get("created_at_i") or h.get("created_at"))})
    return out


def fetch_hackernews(terms: list[str], since: datetime) -> list[dict]:
    out: list[dict] = []
    with _client() as c:
        for term in terms[:5]:  # Algolia has no OR operator, so one query per term
            r = c.get("https://hn.algolia.com/api/v1/search_by_date",
                      params={"query": f'"{term}"', "tags": "(story,comment)", "hitsPerPage": "50",
                              "numericFilters": f"created_at_i>{int(since.timestamp())}"})
            r.raise_for_status()
            out.extend(parse_hn(r.json()))
    return out


# ---------------------------------------------------------------- Bluesky public AppView (free)
def parse_bluesky(data: dict) -> list[dict]:
    out = []
    for p in (data or {}).get("posts") or []:
        uri, author = p.get("uri") or "", p.get("author") or {}
        handle = author.get("handle")
        rkey = uri.rsplit("/", 1)[-1] if uri else None
        record = p.get("record") or {}
        if not uri:
            continue
        out.append({"source": "bluesky", "kind": "mention", "external_id": uri[:300],
                    "url": f"https://bsky.app/profile/{handle}/post/{rkey}" if handle and rkey else None,
                    "author": handle, "title": None, "text": _clean(record.get("text")), "rating": None,
                    "published_at": _dt(record.get("createdAt") or p.get("indexedAt")),
                    "language": (record.get("langs") or [None])[0]})
    return out


def fetch_bluesky(terms: list[str], since: datetime) -> list[dict]:
    out: list[dict] = []
    with _client() as c:
        for term in terms[:5]:
            r = c.get("https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts",
                      params={"q": f'"{term}"' if " " in term else term, "limit": "50", "sort": "latest",
                              "since": since.strftime("%Y-%m-%dT%H:%M:%SZ")})
            r.raise_for_status()
            out.extend(parse_bluesky(r.json()))
    return out


# ---------------------------------------------------------------- Reddit (needs an API app; see terms)
_reddit_token: dict = {}


def parse_reddit(data: dict) -> list[dict]:
    out = []
    for child in ((data or {}).get("data") or {}).get("children") or []:
        d = child.get("data") or {}
        if not d.get("id"):
            continue
        out.append({"source": "reddit", "kind": "mention", "external_id": d.get("name") or d["id"],
                    "url": "https://www.reddit.com" + d["permalink"] if d.get("permalink") else d.get("url"),
                    "author": d.get("author"), "title": _clean(d.get("title"), 500), "text": _clean(d.get("selftext")),
                    "rating": None, "published_at": _dt(d.get("created_utc"))})
    return out


def _reddit_auth(c: httpx.Client) -> str:
    now = time.time()
    if _reddit_token.get("exp", 0) > now + 60:
        return _reddit_token["token"]
    r = c.post("https://www.reddit.com/api/v1/access_token", data={"grant_type": "client_credentials"},
               auth=(os.environ["REDDIT_CLIENT_ID"], os.environ["REDDIT_CLIENT_SECRET"]))
    r.raise_for_status()
    body = r.json()
    _reddit_token.update(token=body["access_token"], exp=now + int(body.get("expires_in", 3600)))
    return _reddit_token["token"]


def fetch_reddit(terms: list[str], since: datetime) -> list[dict]:
    with _client() as c:
        token = _reddit_auth(c)
        r = c.get("https://oauth.reddit.com/search", headers={"Authorization": f"bearer {token}"},
                  params={"q": terms_query(terms), "sort": "new", "t": "week", "limit": "100", "type": "link"})
        r.raise_for_status()
    return [m for m in parse_reddit(r.json()) if m["published_at"] and m["published_at"] >= since]


# ---------------------------------------------------------------- Apple App Store reviews (public RSS)
def parse_apple(data: dict, app_id: str) -> list[dict]:
    entries = ((data or {}).get("feed") or {}).get("entry") or []
    if isinstance(entries, dict):
        entries = [entries]
    out = []
    for e in entries:
        rating = (e.get("im:rating") or {}).get("label")
        if rating is None:  # the first entry of older feeds describes the app itself
            continue
        rid = (e.get("id") or {}).get("label")
        out.append({"source": "apple", "kind": "review", "external_id": str(rid)[:300],
                    "url": f"https://apps.apple.com/app/id{app_id}",
                    "author": ((e.get("author") or {}).get("name") or {}).get("label"),
                    "title": _clean((e.get("title") or {}).get("label"), 500),
                    "text": _clean((e.get("content") or {}).get("label")),
                    "rating": int(rating), "published_at": _dt((e.get("updated") or {}).get("label"))})
    return out


def fetch_apple(app_id: str, country: str = "us", pages: int = 2) -> list[dict]:
    if not APPLE_ID_RE.match(app_id or "") or not COUNTRY_RE.match(country or ""):
        raise ValueError("invalid App Store id or country")
    out: list[dict] = []
    with _client() as c:
        for page in range(1, pages + 1):
            r = c.get(f"https://itunes.apple.com/{country}/rss/customerreviews/page={page}/id={app_id}/sortBy=mostRecent/json")
            r.raise_for_status()
            got = parse_apple(r.json(), app_id)
            out.extend(got)
            if len(got) < 50:
                break
    return out


# ---------------------------------------------------------------- Google reviews (Places API, paid, live only)
def parse_google(data: dict) -> dict:
    reviews = []
    for rv in (data or {}).get("reviews") or []:
        reviews.append({"author": (rv.get("authorAttribution") or {}).get("displayName"),
                        "author_url": (rv.get("authorAttribution") or {}).get("uri"),
                        "rating": rv.get("rating"), "text": ((rv.get("text") or rv.get("originalText") or {}).get("text")),
                        "when": rv.get("relativePublishTimeDescription"), "published_at": rv.get("publishTime"),
                        "url": rv.get("googleMapsUri")})
    return {"name": ((data or {}).get("displayName") or {}).get("text"), "rating": (data or {}).get("rating"),
            "count": (data or {}).get("userRatingCount"), "maps_url": (data or {}).get("googleMapsUri"),
            "reviews": reviews}


def fetch_google(place_id: str) -> dict:
    """Live lookup. Google's terms do not allow storing review content, so nothing from here is saved."""
    if not PLACE_ID_RE.match(place_id or ""):
        raise ValueError("invalid Google place id")
    with _client() as c:
        r = c.get(f"https://places.googleapis.com/v1/places/{quote(place_id)}",
                  headers={"X-Goog-Api-Key": os.environ["GOOGLE_PLACES_API_KEY"],
                           "X-Goog-FieldMask": "displayName,rating,userRatingCount,reviews,googleMapsUri"})
        r.raise_for_status()
    return parse_google(r.json())


# ---------------------------------------------------------------- Web search results (Brave Search API)
def parse_brave(data: dict) -> list[dict]:
    out = []
    for i, res in enumerate((((data or {}).get("web") or {}).get("results") or []), start=1):
        url = res.get("url") or ""
        out.append({"rank": i, "title": _clean(res.get("title"), 300), "url": url,
                    "domain": re.sub(r"^www\.", "", httpx.URL(url).host) if url.startswith("http") else None,
                    "snippet": _clean(res.get("description"), 500)})
    return out


def fetch_search(query: str, country: str | None = None) -> list[dict]:
    params = {"q": query, "count": "20", "safesearch": "off"}
    if country and COUNTRY_RE.match(country):
        params["country"] = country
    with _client() as c:
        r = c.get("https://api.search.brave.com/res/v1/web/search", params=params,
                  headers={"X-Subscription-Token": os.environ["BRAVE_SEARCH_API_KEY"]})
        r.raise_for_status()
    return parse_brave(r.json())


FETCHERS = {"news": fetch_news, "hackernews": fetch_hackernews, "bluesky": fetch_bluesky, "reddit": fetch_reddit}
LOOKBACK_FIRST_POLL = timedelta(days=7)
