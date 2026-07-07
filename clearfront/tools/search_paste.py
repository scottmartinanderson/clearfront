# clearfront/tools/search_paste.py
"""
Paste-leak search.

The original psbdmp.ws backend was permanently shut down (announced 2026; its
domain stopped resolving), so this tool now searches public paste sites via two
live backends:

  1. Have I Been Pwned pastes endpoint (/pasteaccount/{email}), for emails when
     HIBP_API_KEY is set; authoritative, deduplicated paste appearances.
  2. Search-engine dorking restricted to paste sites (Bright Data SERP when
     configured, else DuckDuckGo, no key), works for emails, usernames, or any
     keyword.

Returns a formatted string; never raises on failure.
"""

from __future__ import annotations

import asyncio
import logging
import os
import urllib.parse

import requests

from clearfront.regexes import detect_entity_kind
from clearfront.tools.exceptions import OSINTError, ToolExecutionError
from clearfront.tools.search_footprint import _brightdata_search, _ddg_search

logger = logging.getLogger(__name__)

_HIBP_PASTE_URL = "https://haveibeenpwned.com/api/v3/pasteaccount/{account}"
_USER_AGENT = "Clearfront/2.8.0"
_DEFAULT_TIMEOUT = 20
_MAX_RESULTS = 10
_DDG_RESULTS = 8

# Public paste sites worth dorking with a site: filter.
_PASTE_SITES = [
    "pastebin.com", "paste.ee", "ghostbin.com", "rentry.co",
    "controlc.com", "justpaste.it", "0bin.net", "dpaste.org",
]


def _is_email(query: str) -> bool:
    return detect_entity_kind(query) == "email"


def _fetch_hibp_pastes(email: str, timeout_seconds: int) -> list[dict]:
    """
    Query HIBP's paste endpoint for pastes mentioning email.

    Returns an empty list when the key is absent (the SERP backend still runs)
    or when HIBP has no pastes for the email (404).
    """
    api_key = os.environ.get("HIBP_API_KEY", "")
    if not api_key:
        return []

    headers = {"hibp-api-key": api_key, "user-agent": _USER_AGENT}
    url = _HIBP_PASTE_URL.format(account=urllib.parse.quote(email))
    try:
        response = requests.get(url, headers=headers, timeout=timeout_seconds)
    except requests.RequestException as exc:
        raise OSINTError(f"Network error querying HIBP pastes: {exc}") from exc

    if response.status_code == 404:
        return []
    if response.status_code == 401:
        raise OSINTError("Invalid HIBP API key.")
    if response.status_code == 429:
        raise OSINTError("HIBP rate limit exceeded. Wait 1 second and retry.")
    if response.status_code != 200:
        raise ToolExecutionError(f"HIBP pastes returned HTTP {response.status_code}.")

    data = response.json()
    return data if isinstance(data, list) else []


def _paste_dork(query: str) -> str:
    sites = " OR ".join(f"site:{s}" for s in _PASTE_SITES)
    return f'"{query}" ({sites})'


def _serp_paste_search(query: str, timeout_seconds: int) -> tuple[str, list[dict]]:
    """Run the paste-site dork through Bright Data SERP, or DuckDuckGo if no key.

    Returns (backend_label, results).
    """
    api_key = os.environ.get("BRIGHTDATA_API_KEY", "")
    zone = os.environ.get("BRIGHTDATA_SERP_ZONE", "")
    dork = _paste_dork(query)
    if api_key and zone:
        return "Bright Data SERP", _brightdata_search(dork, api_key, zone, timeout_seconds)
    return "DuckDuckGo (free)", _ddg_search(dork, _DDG_RESULTS, timeout_seconds)


def _hibp_paste_link(source: str, paste_id: str) -> str:
    """Best-effort clickable link for a HIBP paste record."""
    if paste_id and source.lower() == "pastebin":
        return f"https://pastebin.com/{paste_id}"
    return f"(id: {paste_id})" if paste_id else ""


def _format_results(
    query: str,
    hibp_pastes: list[dict],
    serp_backend: str,
    serp_results: list[dict],
) -> str:
    lines = [f"Paste search for '{query}':\n"]
    found = False

    if hibp_pastes:
        found = True
        lines.append(f"[HIBP paste index] {len(hibp_pastes)} paste(s) containing this email:")
        for p in hibp_pastes[:_MAX_RESULTS]:
            source = p.get("Source", "?")
            link = _hibp_paste_link(source, p.get("Id", ""))
            date = p.get("Date", "") or "unknown date"
            emails = p.get("EmailCount", "")
            suffix = f", {emails} emails" if emails else ""
            lines.append(f"  [+] {source}: {link} ({date}{suffix})")
        lines.append("")

    if serp_results:
        found = True
        lines.append(f"[Paste-site search · {serp_backend}] {len(serp_results)} result(s):")
        for r in serp_results[:_MAX_RESULTS]:
            lines.append(f"  [+] {r['url']}")
            if r.get("snippet"):
                lines.append(f"      {r['snippet']}")
        lines.append("")

    if not found:
        return f"No pastes found mentioning '{query}'."

    lines.append(
        "Source: HIBP paste index + search-engine dorking of public paste sites. "
        "Treat these as leads, not proof, verify before relying on them."
    )
    return "\n".join(lines).rstrip()


async def run_paste_osint(
    query: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Search public paste sites for query.

    For emails, queries the HIBP paste index (when HIBP_API_KEY is set) AND
    dorks public paste sites via search engines. For usernames/keywords, runs
    the paste-site dork only. Returns a descriptive error string on failure
    rather than raising.

    Parameters
    ----------
    query:
        Email address, username, or keyword to search for.
    timeout_seconds:
        Per-request timeout in seconds.

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    query = query.strip()
    if not query:
        return "Invalid input: query must not be empty."

    logger.info("Starting paste search for: %s", query)
    hibp_pastes: list[dict] = []
    serp_backend, serp_results = "", []
    errors: list[str] = []

    if _is_email(query):
        try:
            hibp_pastes = await asyncio.to_thread(_fetch_hibp_pastes, query, timeout_seconds)
        except OSINTError as exc:
            errors.append(f"HIBP pastes: {exc}")

    try:
        serp_backend, serp_results = await asyncio.to_thread(
            _serp_paste_search, query, timeout_seconds
        )
    except OSINTError as exc:
        errors.append(f"paste-site search: {exc}")
    except Exception as exc:  # noqa: BLE001, never crash the agent
        logger.exception("Unexpected error during paste-site search.")
        errors.append(f"paste-site search: {exc}")

    # Only surface an error if BOTH backends produced nothing usable.
    if errors and not (hibp_pastes or serp_results):
        return "Scan error: " + "; ".join(errors)

    logger.info("Paste search complete for: %s", query)
    return _format_results(query, hibp_pastes, serp_backend, serp_results)
