# clearfront/tools/search_emailrep.py
"""
EmailRep.io OSINT module.

Queries the EmailRep.io API for an email address's reputation and footprint
summary: an aggregate "what the internet knows about this address" signal drawn
from social/professional profiles, breaches, credential leaks, and spam/abuse
lists. The most useful footprint field is details.profiles (the platforms the
address has been seen on), which complements per-site enumeration.

EmailRep disabled its unauthenticated tier in 2025, so a (free) API key is now
required: request one at https://emailrep.io/free and set EMAILREP_API_KEY.
Degrades gracefully to a clear "needs key" message when absent. Returns a
formatted string; never raises.
"""

from __future__ import annotations

import asyncio
import logging
import os

import aiohttp

logger = logging.getLogger(__name__)

_API_URL = "https://emailrep.io/{email}"
_DEFAULT_TIMEOUT = 15
_HEADERS_BASE = {"User-Agent": "CLEARFRONT-OSINT", "Accept": "application/json"}

_MISSING_KEY_ERROR = (
    "Scan error: EMAILREP_API_KEY is not set (EmailRep disabled its keyless tier). "
    "Request a free key at https://emailrep.io/free and add it to .env."
)


def _raise_for_status(status: int) -> None:
    if status == 400:
        raise ValueError("EmailRep: invalid email address.")
    if status in (401, 403):
        raise ValueError("EmailRep: invalid or unauthorized API key.")
    if status == 429:
        raise ValueError("EmailRep: rate limit exceeded (or key required).")
    if status != 200:
        raise ValueError(f"EmailRep returned HTTP {status}.")


async def _fetch_emailrep_data(email: str, api_key: str, timeout: int) -> dict:
    headers = {**_HEADERS_BASE, "Key": api_key}
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
        async with session.get(_API_URL.format(email=email), headers=headers) as resp:
            _raise_for_status(resp.status)
            return await resp.json(content_type=None)


def _format_emailrep(data: dict, email: str) -> str:
    details = data.get("details") or {}
    lines = [f"EmailRep reputation for '{email}':", ""]
    lines.append(f"[+] Reputation: {data.get('reputation', 'unknown')}")
    lines.append(f"[+] Suspicious: {bool(data.get('suspicious'))}")
    refs = data.get("references")
    if refs is not None:
        lines.append(f"[+] References (sightings): {refs}")

    # Footprint pivot: platforms the address has been seen on.
    profiles = [p for p in (details.get("profiles") or []) if p]
    if profiles:
        lines.append("")
        lines.append(f"Profiles seen ({len(profiles)}): " + ", ".join(profiles))

    # Risk flags: only surface the ones that are set.
    flag_map = {
        "data_breach": "appeared in a data breach",
        "credentials_leaked": "credentials leaked",
        "credentials_leaked_recent": "credentials leaked recently",
        "malicious_activity": "malicious activity",
        "malicious_activity_recent": "malicious activity recently",
        "blacklisted": "blacklisted",
        "spam": "on spam lists",
    }
    active = [desc for key, desc in flag_map.items() if details.get(key)]
    if active:
        lines.append("")
        lines.append("Risk flags: " + "; ".join(active) + ".")

    first_seen, last_seen = details.get("first_seen"), details.get("last_seen")
    if first_seen and first_seen != "never":
        lines.append(f"[+] First seen: {first_seen}")
    if last_seen and last_seen != "never":
        lines.append(f"[+] Last seen: {last_seen}")

    context = []
    if details.get("disposable"):
        context.append("disposable address")
    if details.get("free_provider"):
        context.append("free provider")
    if details.get("deliverable") is False:
        context.append("not deliverable")
    if context:
        lines.append(f"[+] Context: {', '.join(context)}.")

    lines += [
        "",
        "Source: EmailRep.io aggregate reputation (profiles, breaches, abuse lists). "
        "Treat as a lead and corroborate before relying on it.",
    ]
    return "\n".join(lines)


async def run_emailrep_osint(
    email: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
    *,
    api_key: str | None = None,
) -> str:
    """
    Query EmailRep.io for an email's reputation and footprint summary.

    Requires EMAILREP_API_KEY (free at emailrep.io/free); returns a clear
    "needs key" message when absent. Returns a descriptive error string on
    failure rather than raising.

    Parameters
    ----------
    email:
        Target email address.
    timeout_seconds:
        HTTP request timeout in seconds.
    api_key:
        Optional explicit key; falls back to the EMAILREP_API_KEY env var.

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    email = (email or "").strip()
    if not email or "@" not in email or email.startswith("-"):
        return "Error: a valid email address is required for an EmailRep lookup."

    resolved_key = api_key or os.environ.get("EMAILREP_API_KEY", "")
    if not resolved_key:
        return _MISSING_KEY_ERROR

    logger.info("Starting EmailRep lookup for: %s", email)
    try:
        data = await _fetch_emailrep_data(email, resolved_key, timeout_seconds)
        return _format_emailrep(data, email)
    except asyncio.TimeoutError:
        return f"Scan error: EmailRep request timed out after {timeout_seconds}s."
    except aiohttp.ClientError as exc:
        return f"Scan error: network error querying EmailRep: {exc}"
    except ValueError as exc:
        return f"Scan error: {exc}"
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected error during EmailRep lookup.")
        return f"Internal error: {exc}"
