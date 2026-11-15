"""CISA Known Exploited Vulnerabilities catalogue, cached in memory for a day."""

import logging
import threading
import time

import httpx

logger = logging.getLogger("projectscore.kev")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TTL = 24 * 3600
_lock = threading.Lock()
_cache: dict = {"ids": frozenset(), "loaded": 0.0}


def parse(catalogue: dict) -> frozenset[str]:
    return frozenset(v["cveID"].upper() for v in catalogue.get("vulnerabilities", []) if v.get("cveID"))


def kev_ids() -> frozenset[str]:
    with _lock:
        if time.time() - _cache["loaded"] < _TTL and _cache["ids"]:
            return _cache["ids"]
        try:
            resp = httpx.get(KEV_URL, timeout=30.0)
            resp.raise_for_status()
            _cache["ids"] = parse(resp.json())
            _cache["loaded"] = time.time()
            logger.info("loaded %d KEV entries", len(_cache["ids"]))
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            logger.warning("could not load the CISA KEV catalogue: %s", exc)
            _cache["loaded"] = time.time() - _TTL + 600  # retry in 10 minutes
        return _cache["ids"]
