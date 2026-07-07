# clearfront/tools/search_greynoise.py
"""
GreyNoise Community API OSINT module.

Answers the question AbuseIPDB and VirusTotal cannot: is this IP part of the
internet's mass-scanning background noise, or is it a targeted actor? Returns
GreyNoise's classification (benign/malicious/unknown), whether the IP is known
'noise' (opportunistic mass scanner) or 'RIOT' (a common benign business service
such as a CDN or cloud provider), the owning organisation, and when it was last
seen.

Free with a GREYNOISE_API_KEY (Community tier, 50 lookups/week); works
unauthenticated at a lower daily limit. Passive single-IP lookup. Because of the
weekly cap this is an analyst-chosen enrichment on an already-surfaced IP, not an
auto-pivot. Returns a formatted string; never raises.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os

import aiohttp

logger = logging.getLogger(__name__)

_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
_DEFAULT_TIMEOUT = 30


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def run_greynoise_osint(ip: str, timeout_seconds: int = _DEFAULT_TIMEOUT) -> str:
    """Look up an IP against the GreyNoise Community API."""
    ip = (ip or "").strip()
    if not _is_ip(ip):
        return "Error: a valid IP address is required for a GreyNoise lookup."

    headers = {"Accept": "application/json"}
    key = os.environ.get("GREYNOISE_API_KEY", "").strip()
    if key:
        headers["key"] = key

    timeout_cfg = aiohttp.ClientTimeout(total=timeout_seconds)
    logger.info("Starting GreyNoise lookup for: %s", ip)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg, headers=headers) as session:
            async with session.get(_COMMUNITY_URL.format(ip=ip)) as resp:
                if resp.status == 404:
                    return (
                        f"[GreyNoise] {ip} has not been observed by GreyNoise "
                        "(no internet scan activity on record)."
                    )
                if resp.status == 429:
                    return (
                        "[GreyNoise] Rate limit reached (Community tier is 50 lookups/week). "
                        "Try later, or set GREYNOISE_API_KEY for the free community allowance."
                    )
                if resp.status == 401:
                    return "[GreyNoise] Invalid GREYNOISE_API_KEY."
                if resp.status != 200:
                    return f"[GreyNoise] Error: HTTP {resp.status} querying GreyNoise."
                data = await resp.json(content_type=None)
    except asyncio.TimeoutError:
        return f"[GreyNoise] Error: request timed out after {timeout_seconds}s."
    except aiohttp.ClientError as exc:
        return f"[GreyNoise] Error: network error querying GreyNoise: {exc}"
    except Exception as exc:  # noqa: BLE001, never crash the agent
        logger.exception("Unexpected error during GreyNoise lookup.")
        return f"[GreyNoise] Internal error: {exc}"

    if not isinstance(data, dict):
        return f"[GreyNoise] No usable data returned for {ip}."

    classification = data.get("classification", "unknown")
    noise = bool(data.get("noise", False))
    riot = bool(data.get("riot", False))
    name = data.get("name", "unknown")
    last_seen = data.get("last_seen", "n/a")

    lines = [f"[GreyNoise] {ip}: classification {classification}."]
    if noise:
        lines.append(
            "[GreyNoise] Flagged as internet background noise "
            "(opportunistic mass scanner, not specifically targeting you)."
        )
    if riot:
        lines.append(f"[GreyNoise] RIOT: known benign common business service ({name}).")
    if not noise and not riot:
        lines.append(
            f"[GreyNoise] Not mass-scanner noise and not a known benign service; org: {name}. "
            "Assessment: more likely a targeted or interesting actor than random scanning."
        )
    lines.append(f"[GreyNoise] Owner: {name}. Last seen: {last_seen}.")
    lines.append("Source: GreyNoise Community API (mass-scan visibility). Passive.")
    return "\n".join(lines)
