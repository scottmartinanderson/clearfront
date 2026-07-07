# clearfront/tools/search_dorks_live.py
"""
Bright Data SERP API integration.

Executes Google dork queries for a target through the Bright Data SERP API,
returning structured results (title, URL, snippet) for each dork.

`generate_dorks` remains fully offline and unchanged; this is a separate,
opt-in tool that requires a Bright Data account.

Request format: POST https://api.brightdata.com/request
  { zone, url, format: "raw", data_format: "parsed_light" }
With format="raw" + data_format="parsed_light", response.json() returns the
parsed SERP data directly as {"organic": [...]}, no envelope wrapper.

Requires BRIGHTDATA_API_KEY and BRIGHTDATA_SERP_ZONE environment variables.

Free tier: 5,000 requests/month, see clearfront.brightdata.BRIGHTDATA_LINK_CLI
"""

from __future__ import annotations

import asyncio
import logging
import os
import urllib.parse

import requests

from clearfront.brightdata import BRIGHTDATA_LINK_CLI
from clearfront.serp import preferred_backend, serper_search
from clearfront.tools.exceptions import OSINTError, ToolExecutionError
from clearfront.tools.generate_dorks import _DORK_TEMPLATES

logger = logging.getLogger(__name__)

_API_URL = "https://api.brightdata.com/request"
_DEFAULT_TIMEOUT = 30
_DEFAULT_MAX_DORKS = 5
_GOOGLE_SEARCH_BASE = "https://www.google.com/search?q="

_MISSING_BACKEND_MSG = (
    "Scan error: no SERP backend configured. Set SERPER_API_KEY "
    "(cheap, 2,500 free queries at https://serper.dev), or BRIGHTDATA_API_KEY "
    f"+ BRIGHTDATA_SERP_ZONE (free tier 5,000/month, {BRIGHTDATA_LINK_CLI})."
)


def _build_google_url(dork_query: str) -> str:
    return f"{_GOOGLE_SEARCH_BASE}{urllib.parse.quote(dork_query)}&hl=en&gl=us"


def _fetch_serp(url: str, api_key: str, zone: str, timeout: int) -> dict:
    try:
        response = requests.post(
            _API_URL,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
            json={"zone": zone, "url": url, "format": "raw", "data_format": "parsed_light"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise OSINTError(f"Network error querying Bright Data SERP: {exc}") from exc

    if response.status_code == 401:
        raise OSINTError("Bright Data SERP: invalid API key.")
    if response.status_code == 403:
        raise OSINTError("Bright Data SERP: forbidden, check zone permissions.")
    if response.status_code == 429:
        raise OSINTError("Bright Data SERP: rate limit exceeded.")
    if response.status_code != 200:
        raise ToolExecutionError(f"Bright Data SERP returned HTTP {response.status_code}.")

    # format="raw" + data_format="parsed_light": response body IS the parsed JSON dict
    return response.json()


def _extract_organic(data: dict) -> list[dict]:
    organic = data.get("organic", [])
    results = []
    for item in organic[:5]:
        title = item.get("title", "")
        # Primary field is 'link'; defensive fallback to 'url'
        link = item.get("link", "") or item.get("url", "")
        snippet = item.get("description", "") or item.get("snippet", "")
        if link:
            results.append({"title": title, "url": link, "snippet": snippet})
    return results


def _search_one(query: str, backend: str, api_key: str, zone: str, timeout: int) -> list[dict]:
    """Run one dork query through the active backend. Returns [{title, url, snippet}]."""
    if backend == "serper":
        return serper_search(query, num=5, timeout=timeout)
    data = _fetch_serp(_build_google_url(query), api_key, zone, timeout)
    return _extract_organic(data)


async def run_dorks_live_osint(
    target: str,
    max_dorks: int = _DEFAULT_MAX_DORKS,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Execute Google dork queries for *target* via the Bright Data SERP API.

    Reuses the same dork templates as ``generate_dorks`` but fetches live
    search results instead of generating URLs. Each dork is a separate API
    call, Bright Data bills per successful request.

    Requires ``BRIGHTDATA_API_KEY`` and ``BRIGHTDATA_SERP_ZONE`` environment variables.

    Returns
    -------
    str
        Formatted results or descriptive error message.
    """
    target = target.strip()
    if not target:
        return "Invalid input: target must not be empty."

    backend = preferred_backend()
    if backend == "duckduckgo":
        # dorks_live needs a Google SERP backend; DuckDuckGo is footprint-only.
        return _MISSING_BACKEND_MSG
    api_key = os.environ.get("BRIGHTDATA_API_KEY", "")
    zone = os.environ.get("BRIGHTDATA_SERP_ZONE", "")

    dorks = _DORK_TEMPLATES[:max_dorks]
    logger.info("Starting live dork search for '%s' via %s (%d dorks)", target, backend, len(dorks))

    lines = [f"Live dork search for '{target}' via {backend} ({len(dorks)} queries):\n"]
    error_count = 0

    for template in dorks:
        query = template.format(target=target)
        lines.append(f"[+] Dork: {query}")
        try:
            results = await asyncio.to_thread(
                _search_one, query, backend, api_key, zone, timeout_seconds
            )
            if results:
                for r in results:
                    lines.append(f"    Title:   {r['title']}")
                    lines.append(f"    URL:     {r['url']}")
                    if r["snippet"]:
                        lines.append(f"    Snippet: {r['snippet'][:200]}")
                    lines.append("")
            else:
                lines.append("    (no organic results)")
                lines.append("")
        except OSINTError as exc:
            error_count += 1
            logger.warning("SERP dork failed: %s", exc)
            lines.append(f"    (error: {exc})")
            lines.append("")
        except Exception as exc:
            error_count += 1
            logger.exception("Unexpected error during live dork execution.")
            lines.append(f"    (internal error: {exc})")
            lines.append("")

    if error_count == len(dorks):
        return (
            f"Scan error: all SERP requests failed via {backend}. "
            "Check your SERP backend credentials (SERPER_API_KEY or BRIGHTDATA_*)."
        )

    logger.info("Live dork search complete for: %s", target)
    return "\n".join(lines)
