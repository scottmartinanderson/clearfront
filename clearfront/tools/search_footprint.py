# clearfront/tools/search_footprint.py
"""
Search-engine footprint tool.

Detects the entity type of the target (email, username, domain, phone, or full
name), selects entity-type-aware query templates, and runs them through a search
backend. Returns structured results plus graph-compatible ``[Footprint] URL:``
lines that the Entity Correlation Graph extractor parses.

Backends (selected automatically):
  - Bright Data SERP API  - used when BRIGHTDATA_API_KEY and BRIGHTDATA_SERP_ZONE
    are set. Reliable, Google results, billable (free tier: 5,000 req/month).
  - DuckDuckGo (free)      - the default fallback when Bright Data is not
    configured. No API key; results are real indexed pages, so this avoids the
    false positives of blind username probing.

Differs from ``search_dorks_live`` (generic dork templates regardless of type).
"""

from __future__ import annotations

import asyncio
import logging
import os
import urllib.parse
from urllib.parse import urlparse

import requests

from clearfront.regexes import detect_entity_kind
from clearfront.serp import preferred_backend, serper_search
from clearfront.tools.exceptions import OSINTError, ToolExecutionError

logger = logging.getLogger(__name__)

_API_URL = "https://api.brightdata.com/request"
_DEFAULT_TIMEOUT = 30
_DEFAULT_MAX_QUERIES = 3
_DDG_RESULTS_PER_QUERY = 6
_GOOGLE_SEARCH_BASE = "https://www.google.com/search?q="

# ---------------------------------------------------------------------------
# Entity-type-aware query templates
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, list[str]] = {
    "email": [
        '"{target}"',
        '"{target}" (site:pastebin.com OR site:github.com OR site:trello.com)',
        '"{target}" -site:google.com',
    ],
    "username": [
        '"{target}"',
        '"{target}" (site:github.com OR site:twitter.com OR site:reddit.com OR site:linkedin.com)',
        '"{target}" profile',
    ],
    "domain": [
        "site:{target}",
        '"{target}" -site:{target}',
        'inurl:"{target}"',
    ],
    "phone": [
        '"{target}"',
        '"{target}" (site:truecaller.com OR site:whitepages.com OR site:spokeo.com)',
    ],
    "person": [
        '"{target}"',
        '"{target}" (site:linkedin.com OR site:twitter.com OR site:facebook.com)',
        '"{target}" resume OR cv OR portfolio',
    ],
}

# ip/url/hash - SERP footprint not applicable for these entity types
_UNSUPPORTED_KINDS = frozenset({"ip", "url", "hash"})


# ---------------------------------------------------------------------------
# Search backends - each returns a list of {rank, title, url, display_url, snippet}
# ---------------------------------------------------------------------------


def _build_google_url(query: str) -> str:
    """Build a Google search URL with q= first (improves Bright Data success rate)."""
    return f"{_GOOGLE_SEARCH_BASE}{urllib.parse.quote(query)}&hl=en&gl=us"


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
        raise OSINTError("Bright Data SERP: forbidden - check zone permissions.")
    if response.status_code == 429:
        raise OSINTError("Bright Data SERP: rate limit exceeded.")
    if response.status_code != 200:
        raise ToolExecutionError(f"Bright Data SERP returned HTTP {response.status_code}.")

    # format="raw" + data_format="parsed_light": body IS the parsed JSON dict
    return response.json()


def _extract_organic(data: dict) -> list[dict]:
    results = []
    for rank, item in enumerate(data.get("organic", [])[:5], start=1):
        link = item.get("link", "") or item.get("url", "")
        if not link:
            continue
        results.append(
            {
                "rank": rank,
                "title": item.get("title", ""),
                "url": link,
                "display_url": item.get("display_link", "") or urlparse(link).netloc,
                "snippet": (item.get("description", "") or item.get("snippet", ""))[:200],
            }
        )
    return results


def _brightdata_search(query: str, api_key: str, zone: str, timeout: int) -> list[dict]:
    """Run one query through the Bright Data SERP API."""
    data = _fetch_serp(_build_google_url(query), api_key, zone, timeout)
    return _extract_organic(data)


def _ddg_search(query: str, max_results: int, timeout: int) -> list[dict]:
    """Run one query through DuckDuckGo (no API key)."""
    try:
        from ddgs import DDGS

        rows = list(DDGS().text(query, max_results=max_results))
    except Exception as exc:  # ratelimit, network, import, etc.
        raise OSINTError(f"DuckDuckGo search failed: {exc}") from exc

    results: list[dict] = []
    for rank, item in enumerate(rows, start=1):
        url = item.get("href", "") or item.get("url", "")
        if not url:
            continue
        results.append(
            {
                "rank": rank,
                "title": item.get("title", ""),
                "url": url,
                "display_url": urlparse(url).netloc,
                "snippet": (item.get("body", "") or "")[:200],
            }
        )
    return results


def _domain_from_url(url: str) -> str:
    """Extract netloc from a URL, stripping www. prefix."""
    try:
        host = urlparse(url).netloc.lower()
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def run_footprint_osint(
    target: str,
    max_queries: int = _DEFAULT_MAX_QUERIES,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Collect a target's public search-engine footprint.

    Detects the entity type of *target* (email, username, domain, phone, or full
    name) and runs entity-type-aware search queries through Bright Data's SERP
    API when configured, otherwise DuckDuckGo (free, no key). Returns structured
    results plus ``[Footprint] URL:`` lines for the Entity Correlation Graph.

    Parameters
    ----------
    target:
        Any OSINT target: email, username, domain, phone number, or full name.
    max_queries:
        Maximum number of search calls to make (default 3).
    timeout_seconds:
        Per-request timeout.

    Returns
    -------
    str
        Formatted footprint report with graph-compatible URL lines, or a
        descriptive error message.
    """
    target = target.strip()
    if not target:
        return "Invalid input: target must not be empty."

    kind = detect_entity_kind(target)
    if kind in _UNSUPPORTED_KINDS:
        return (
            f"Scan error: footprint search is not supported for entity type '{kind}'. "
            "Use search_virustotal, search_ip, or search_shodan instead."
        )

    api_key = os.environ.get("BRIGHTDATA_API_KEY", "")
    zone = os.environ.get("BRIGHTDATA_SERP_ZONE", "")
    backend_key = preferred_backend()  # 'serper' | 'brightdata' | 'duckduckgo'
    backend = {
        "serper": "Serper.dev",
        "brightdata": "Bright Data SERP",
        "duckduckgo": "DuckDuckGo (free)",
    }[backend_key]

    templates = _TEMPLATES.get(kind, _TEMPLATES["person"])
    queries = [t.format(target=target) for t in templates[:max_queries]]

    logger.info(
        "Starting footprint search for '%s' (type=%s, backend=%s, %d queries)",
        target, kind, backend, len(queries),
    )

    lines: list[str] = [
        f"[Footprint] {target}  |  type: {kind}  |  backend: {backend}  |  "
        f"{len(queries)} quer{'y' if len(queries) == 1 else 'ies'}\n"
    ]

    seen_urls: set[str] = set()
    seen_domains: set[str] = set()
    discovered_urls: list[str] = []
    error_count = 0

    for i, query in enumerate(queries, start=1):
        lines.append(f"[+] Query {i}/{len(queries)}: {query}")
        try:
            if backend_key == "serper":
                raw = await asyncio.to_thread(
                    serper_search, query, _DDG_RESULTS_PER_QUERY, timeout_seconds
                )
                results = [
                    {
                        "rank": i,
                        "title": r["title"],
                        "url": r["url"],
                        "display_url": urlparse(r["url"]).netloc,
                        "snippet": (r["snippet"] or "")[:200],
                    }
                    for i, r in enumerate(raw, start=1)
                ]
            elif backend_key == "brightdata":
                results = await asyncio.to_thread(
                    _brightdata_search, query, api_key, zone, timeout_seconds
                )
            else:
                results = await asyncio.to_thread(
                    _ddg_search, query, _DDG_RESULTS_PER_QUERY, timeout_seconds
                )
            if results:
                for r in results:
                    url_key = r["url"].rstrip("/")
                    if url_key in seen_urls:
                        continue
                    seen_urls.add(url_key)
                    discovered_urls.append(r["url"])
                    lines.append(f"    {r['rank']}. {r['title']}")
                    lines.append(f"       URL:     {r['url']}")
                    if r["display_url"]:
                        lines.append(f"       Display: {r['display_url']}")
                    if r["snippet"]:
                        lines.append(f"       Snippet: {r['snippet']}")
                    lines.append("")
            else:
                lines.append("    (no organic results)")
                lines.append("")
        except OSINTError as exc:
            error_count += 1
            logger.warning("Footprint query failed: %s", exc)
            lines.append(f"    (error: {exc})")
            lines.append("")
        except Exception as exc:
            error_count += 1
            logger.exception("Unexpected error in footprint query.")
            lines.append(f"    (internal error: {exc})")
            lines.append("")

    if error_count == len(queries):
        if backend_key == "duckduckgo":
            return (
                "Scan error: all DuckDuckGo searches failed (possibly rate-limited). "
                "Try again shortly, or set SERPER_API_KEY / Bright Data for reliable results."
            )
        return (
            f"Scan error: all SERP requests failed via {backend}. "
            "Check your SERP backend credentials."
        )

    # Append graph-compatible summary lines (parsed by _extract_footprint in extractors.py)
    if discovered_urls:
        lines.append("-- Discovered URLs " + "-" * 42)
        for url in discovered_urls:
            lines.append(f"[Footprint] URL: {url}")
            domain = _domain_from_url(url)
            if domain and domain not in seen_domains:
                seen_domains.add(domain)
                lines.append(f"[Footprint] Domain: {domain}")

    logger.info(
        "Footprint search complete for '%s' (%s): %d URLs, %d domains",
        target, backend, len(discovered_urls), len(seen_domains),
    )
    return "\n".join(lines)
