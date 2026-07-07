# clearfront/tools/whatsmyname.py
"""
WhatsMyName username checker, a helper for search_username, NOT a standalone tool.

Checks a username against a bundled, filtered subset of the WhatsMyName project's
site list (the services not already covered by maigret), broadening username
footprint coverage with modern/niche platforms. Each WhatsMyName entry carries an
exact "account exists" detection string (e_string) plus status code (e_code), so a
match is high-confidence (it lands in search_username's CONFIRMED tier).

Data: clearfront/tools/data/wmn-data-unique.json, a filtered adaptation of WhatsMyName
(https://github.com/WebBreacher/WhatsMyName), Copyright (C) Micah Hoffman, licensed
CC BY-SA 4.0 (https://creativecommons.org/licenses/by-sa/4.0/). See the NOTICE in
that directory. Returns confirmed (site, url) pairs; never raises.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import aiohttp

logger = logging.getLogger(__name__)

_DATA_PATH = Path(__file__).parent / "data" / "wmn-data-unique.json"
_CONCURRENCY = 30
_PER_SITE_TIMEOUT = 6
_READ_BYTES = 60_000
_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_sites_cache: list[dict] | None = None


def _load_sites() -> list[dict]:
    """Load and cache the bundled WhatsMyName site list. Returns [] on any error."""
    global _sites_cache
    if _sites_cache is None:
        try:
            _sites_cache = json.loads(_DATA_PATH.read_text(encoding="utf-8")).get("sites", [])
        except Exception:
            logger.exception("Failed to load WhatsMyName data from %s", _DATA_PATH)
            _sites_cache = []
    return _sites_cache


def _account_exists(status: int, body: str, site: dict) -> bool:
    """WhatsMyName 'exists' rule: status == e_code AND e_string present in body.

    Requires a non-empty e_string so we never confirm on a bare 200 (which many
    sites return for any username). Conservative by design: protected/JS sites
    that do not echo the marker are treated as not-found, not false positives.
    """
    e_string = site.get("e_string") or ""
    if not e_string:
        return False
    return status == site.get("e_code") and e_string in body


async def run_whatsmyname_check(
    username: str,
    *,
    concurrency: int = _CONCURRENCY,
) -> list[tuple[str, str]]:
    """
    Check username against the bundled WhatsMyName subset.

    Returns a sorted list of (site_name, profile_url) for confirmed accounts.
    Network errors per site are swallowed (treated as not-found); the function
    never raises.
    """
    sites = _load_sites()
    username = (username or "").strip()
    if not sites or not username or username.startswith("-"):
        return []

    sem = asyncio.Semaphore(concurrency)
    headers = {"User-Agent": _UA, "Accept-Language": "en-US,en;q=0.9"}
    timeout = aiohttp.ClientTimeout(total=_PER_SITE_TIMEOUT)
    found: list[tuple[str, str]] = []

    async def _one(session: aiohttp.ClientSession, site: dict) -> None:
        uri = site.get("uri_check") or ""
        if "{account}" not in uri:
            return
        url = uri.replace("{account}", username)
        async with sem:
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    body = (await resp.content.read(_READ_BYTES)).decode("utf-8", errors="ignore")
                    if _account_exists(resp.status, body, site):
                        found.append((site.get("name") or url, url))
            except Exception:
                return  # could not check this site; do not claim found

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            await asyncio.gather(*(_one(session, s) for s in sites))
    except Exception:
        logger.exception("WhatsMyName check failed for: %s", username)
        return found

    found.sort(key=lambda x: x[0].lower())
    logger.info("WhatsMyName: %d confirmed for '%s'", len(found), username)
    return found
