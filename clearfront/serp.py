# clearfront/serp.py
"""
Pluggable SERP (Google search results) backend.

Google-results search powers search_dorks_live and search_footprint. This module
lets those tools reach Google through more than one provider so they do not
depend on a single vendor:

  1. Serper.dev        - if SERPER_API_KEY is set. Cheap (~$1/1k, 2,500 free),
                         fast, simple. Preferred when available.
  2. Bright Data SERP  - if BRIGHTDATA_API_KEY + BRIGHTDATA_SERP_ZONE are set.
  3. DuckDuckGo (free) - keyless fallback (used by search_footprint).

The Serper backend returns a normalised list of {"title", "url", "snippet"}
dicts, matching the shape the tools already use for Bright Data results.
"""

from __future__ import annotations

import os

import requests

from clearfront.tools.exceptions import OSINTError, ToolExecutionError

_SERPER_URL = "https://google.serper.dev/search"


def serper_available() -> bool:
    """True if a Serper.dev key is configured."""
    return bool(os.environ.get("SERPER_API_KEY", "").strip())


def brightdata_available() -> bool:
    """True if a Bright Data SERP zone is configured."""
    return bool(
        os.environ.get("BRIGHTDATA_API_KEY", "").strip()
        and os.environ.get("BRIGHTDATA_SERP_ZONE", "").strip()
    )


def preferred_backend() -> str:
    """Return the active Google-SERP backend: 'serper', 'brightdata', or 'duckduckgo'."""
    if serper_available():
        return "serper"
    if brightdata_available():
        return "brightdata"
    return "duckduckgo"


def serper_search(query: str, num: int = 5, timeout: int = 30) -> list[dict]:
    """Run one query through Serper.dev. Returns a list of {title, url, snippet}.

    Raises OSINTError / ToolExecutionError on failure so callers can degrade
    gracefully, matching the Bright Data backend's error contract.
    """
    api_key = os.environ.get("SERPER_API_KEY", "").strip()
    if not api_key:
        raise OSINTError("SERPER_API_KEY is not set.")
    try:
        resp = requests.post(
            _SERPER_URL,
            headers={"X-API-KEY": api_key, "Content-Type": "application/json"},
            json={"q": query, "num": num, "gl": "us", "hl": "en"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        raise OSINTError(f"Network error querying Serper.dev: {exc}") from exc

    if resp.status_code in (401, 403):
        raise OSINTError("Serper.dev: invalid or unauthorized SERPER_API_KEY.")
    if resp.status_code == 429:
        raise OSINTError("Serper.dev: rate limit exceeded.")
    if resp.status_code != 200:
        raise ToolExecutionError(f"Serper.dev returned HTTP {resp.status_code}.")

    try:
        data = resp.json()
    except ValueError as exc:
        raise ToolExecutionError("Serper.dev returned a non-JSON response.") from exc

    results: list[dict] = []
    for item in (data.get("organic") or [])[:num]:
        link = item.get("link", "") or item.get("url", "")
        if link:
            results.append(
                {
                    "title": item.get("title", ""),
                    "url": link,
                    "snippet": item.get("snippet", "") or item.get("description", ""),
                }
            )
    return results
