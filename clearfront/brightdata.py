"""
Bright Data referral link and shared account checks.

Bright Data powers the optional search_dorks_live / search_footprint / scrape_url
tools (a free tier is available). This is the single place the sign-up URL is
defined, so every surface (CLI / MCP / web / docs) shows the same link in its
missing-key setup message. It is a referral link: signing up through it supports
Clearfront's development at no extra cost to you.

A suspended or unpaid Bright Data account does not answer with an auth error.
POST /request returns HTTP 200 with a zero-length body, which is indistinguishable
from a page that scraped to nothing. Every caller must therefore treat an empty
200 as a failure and call `empty_body_reason` to name the cause, so a dead backend
is never reported to the analyst as an absence of evidence.
"""

from __future__ import annotations

import logging
import time

import requests

logger = logging.getLogger(__name__)

_MAIN = "https://get.brightdata.com/8ygvxztgo5dr"

BRIGHTDATA_LINK_CLI = _MAIN
BRIGHTDATA_LINK_MCP = _MAIN
BRIGHTDATA_LINK_WEB = _MAIN
BRIGHTDATA_LINK_README = _MAIN
BRIGHTDATA_LINK_DOCS = _MAIN
BRIGHTDATA_LINK_CHANGELOG = _MAIN

BRIGHTDATA_DASHBOARD = "https://brightdata.com/cp"

_STATUS_URL = "https://api.brightdata.com/status"
_STATUS_TIMEOUT = 10
_STATUS_CACHE_TTL = 60.0

# api_key -> (monotonic timestamp, reason or "")
_status_cache: dict[str, tuple[float, str]] = {}


def _clear_status_cache() -> None:
    """Drop the cached account status. For tests."""
    _status_cache.clear()


def account_blocked_reason(api_key: str, *, timeout: int = _STATUS_TIMEOUT) -> str | None:
    """
    Return why the Bright Data account cannot make requests, or None if it can.

    Answers from ``GET /status``, which reports ``can_make_requests`` even when
    ``/request`` itself returns a bare HTTP 200. The result is cached for a minute
    so a failing sweep probes once rather than once per tool call.
    """
    if not api_key:
        return None

    now = time.monotonic()
    cached = _status_cache.get(api_key)
    if cached is not None and now - cached[0] < _STATUS_CACHE_TTL:
        return cached[1] or None

    reason = ""
    try:
        response = requests.get(
            _STATUS_URL,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict) and data.get("can_make_requests") is False:
                status = str(data.get("status") or "unknown").strip() or "unknown"
                reason = (
                    f"Bright Data account status is '{status}' and it cannot make "
                    f"requests. No data was collected. Reactivate the account at "
                    f"{BRIGHTDATA_DASHBOARD}"
                )
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Bright Data status probe failed: %s", exc)

    _status_cache[api_key] = (now, reason)
    return reason or None


def empty_body_reason(api_key: str, service: str) -> str:
    """
    Explain an HTTP 200 carrying a zero-length body from *service*.

    Names the account state when the status endpoint gives one, and otherwise says
    plainly that nothing came back. Either way the caller reports a failure rather
    than an empty result.
    """
    blocked = account_blocked_reason(api_key)
    if blocked:
        return blocked
    return (
        f"{service} returned HTTP 200 with an empty body. No data was collected. "
        f"Check the zone is active at {BRIGHTDATA_DASHBOARD}/zones"
    )
