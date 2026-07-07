# clearfront/tools/search_wayback.py
"""
Wayback Machine (Internet Archive) OSINT module.

Queries the public CDX API for URLs archived under a domain, recovering
deleted, forgotten, or historical pages that no longer resolve publicly. Fully
passive (reads the public archive, never touches the target) and keyless, so it
fits the free tier and the authorized, public-source posture. Pairs with
scrape_url: Wayback finds the historical URLs, scrape_url can fetch a live one.

The archive is a nonprofit shared resource, so the tool keeps concurrency low
and degrades gracefully. Returns a formatted string; never raises.
"""

from __future__ import annotations

import asyncio
import logging

import aiohttp

logger = logging.getLogger(__name__)

_CDX_URL = "https://web.archive.org/cdx/search/cdx"
_DEFAULT_TIMEOUT = 30
_MAX_URLS = 60
_HEADERS = {
    "User-Agent": "CLEARFRONT-OSINT (+https://github.com/scottmartinanderson/clearfront)"
}


def _clean_host(target: str) -> str:
    """Normalise a target into a bare host (drops scheme, path, and wildcards)."""
    t = (target or "").strip().lower()
    t = t.replace("https://", "").replace("http://", "").split("/")[0]
    return t.lstrip("*.").strip(".")


async def run_wayback_osint(target: str, timeout_seconds: int = _DEFAULT_TIMEOUT) -> str:
    """
    List URLs archived under a domain in the Internet Archive.

    Parameters
    ----------
    target:
        A domain (e.g. example.com); subdomains are included.
    timeout_seconds:
        Hard HTTP timeout; the archive can be slow.

    Returns
    -------
    str
        Formatted archived-URL list, or a descriptive unavailable/error message.
    """
    host = _clean_host(target)
    if not host or "." not in host:
        return "Error: a valid domain is required for a Wayback Machine lookup."

    params = {
        "url": host,
        "matchType": "domain",
        "output": "json",
        "collapse": "urlkey",
        "fl": "original,timestamp,statuscode",
        "limit": str(_MAX_URLS),
    }
    timeout_cfg = aiohttp.ClientTimeout(total=timeout_seconds)
    logger.info("Starting Wayback lookup for: %s", host)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg, headers=_HEADERS) as session:
            async with session.get(_CDX_URL, params=params) as resp:
                if resp.status in (429, 502, 503, 504):
                    return (
                        f"[Wayback] Unavailable: the Internet Archive returned HTTP {resp.status} "
                        "(often overloaded). Try again shortly."
                    )
                if resp.status != 200:
                    return f"[Wayback] Error: HTTP {resp.status} querying the Internet Archive."
                try:
                    rows = await resp.json(content_type=None)
                except Exception:
                    return "[Wayback] Unavailable: the archive returned a non-JSON response."
    except asyncio.TimeoutError:
        return f"[Wayback] Unavailable: request timed out after {timeout_seconds}s."
    except aiohttp.ClientError as exc:
        return f"[Wayback] Error: network error querying the Internet Archive: {exc}"
    except Exception as exc:  # noqa: BLE001, never crash the agent
        logger.exception("Unexpected error during Wayback lookup.")
        return f"[Wayback] Internal error: {exc}"

    # CDX JSON is a list whose first row is the field header.
    if not isinstance(rows, list) or len(rows) < 2:
        return f"[Wayback] No archived URLs found for '{host}'."

    data = rows[1:]
    lines = [
        f"[Wayback] {len(data)} archived URL(s) for '{host}' in the Internet Archive"
        + (f" (capped at {_MAX_URLS})" if len(data) >= _MAX_URLS else "")
        + ":"
    ]
    for row in data:
        original = row[0] if len(row) > 0 else ""
        ts = row[1] if len(row) > 1 else ""
        status = row[2] if len(row) > 2 else ""
        if original:
            lines.append(f"[Wayback] URL: {original} (first capture {ts}, status {status})")
    lines.append(
        "Source: Internet Archive Wayback Machine (public CDX index, passive). "
        "May include deleted or forgotten pages that no longer resolve."
    )
    return "\n".join(lines)
