# clearfront/tools/search_ip.py
"""
IP intelligence module.

Queries ipinfo.io to retrieve geolocation, ASN, hostname, and organisation
data for a target IP address. When called with no IP (or "me"/"self"), it
auto-detects the caller's own public IP via ipinfo's self endpoint, so a user
can check their own exposure without first looking up their address.

Free tier: 50k requests/month, no key required. Set IPINFO_TOKEN env var for
higher limits. Returns a formatted string; never raises.
"""

from __future__ import annotations

import asyncio
import logging
import os

import aiohttp

from clearfront.tools.exceptions import OSINTError, ToolExecutionError

logger = logging.getLogger(__name__)

_IPINFO_URL = "https://ipinfo.io/{ip}/json"
# No IP in the path → ipinfo returns the caller's own public IP and its data.
_IPINFO_SELF_URL = "https://ipinfo.io/json"
_DEFAULT_TIMEOUT = 10

# Values that mean "detect my own public IP" rather than a literal target.
_SELF_ALIASES = {"", "me", "self", "mine", "my", "myself"}


def _is_self_lookup(ip: str) -> bool:
    """Return True when ip is empty or a 'my own IP' alias."""
    return ip.strip().lower() in _SELF_ALIASES


def _ipinfo_request(ip: str, api_key: str | None = None) -> tuple[str, dict]:
    """Build the (url, params) for an ipinfo lookup. Pure, easy to unit-test.

    An empty/self-alias ip targets ipinfo's self endpoint (caller's own IP).
    """
    token = api_key or os.environ.get("IPINFO_TOKEN", "")
    params: dict = {"token": token} if token else {}
    url = _IPINFO_SELF_URL if _is_self_lookup(ip) else _IPINFO_URL.format(ip=ip)
    return url, params


async def _fetch_ip_data(ip: str, timeout_seconds: int, api_key: str | None = None) -> dict:
    """
    Query ipinfo.io for geolocation and ASN data (async, non-blocking).

    Raises
    ------
    OSINTError
        On rate limiting or network failures.
    ToolExecutionError
        On unexpected HTTP status codes.
    """
    url, params = _ipinfo_request(ip, api_key)
    timeout_cfg = aiohttp.ClientTimeout(total=timeout_seconds)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            async with session.get(url, params=params) as resp:
                if resp.status == 429:
                    raise OSINTError(
                        "ipinfo.io rate limit exceeded. "
                        "Set IPINFO_TOKEN for higher limits: https://ipinfo.io/signup"
                    )
                if resp.status != 200:
                    raise ToolExecutionError(f"ipinfo.io returned HTTP {resp.status}.")
                return await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        raise OSINTError(f"Network error querying ipinfo.io: {exc}") from exc


def _format_ip_results(data: dict, ip: str) -> str:
    """Return a structured string describing IP intelligence."""
    if "bogon" in data:
        bogon_ip = data.get("ip") or ip or "that address"
        return f"'{bogon_ip}' is a bogon/private address, no public data available."

    is_self = _is_self_lookup(ip)
    display_ip = data.get("ip") or ip or "unknown"

    if is_self:
        header = f"IP intelligence for your public IP '{display_ip}':\n"
    else:
        header = f"IP intelligence for '{display_ip}':\n"

    fields = ["ip", "hostname", "org", "city", "region", "country", "loc", "timezone"]
    lines = [header]
    for field in fields:
        value = data.get(field)
        if value:
            lines.append(f"[+] {field.capitalize()}: {value}")

    if is_self:
        lines.append(
            "\n[i] This is the public IP the internet currently sees you as. "
            "On a VPN/proxy this is the exit IP, not your real address."
        )
    return "\n".join(lines)


async def run_ip_osint(
    ip: str = "",
    timeout_seconds: int = _DEFAULT_TIMEOUT,
    *,
    api_key: str | None = None,
) -> str:
    """
    Retrieve geolocation and ASN data for ip via ipinfo.io.

    If ip is empty (or "me"/"self"), auto-detect and report the caller's own
    public IP. Returns a descriptive error string on failure rather than raising.

    Parameters
    ----------
    ip:
        Target IPv4 or IPv6 address. Empty/"me"/"self" → detect own public IP.
    timeout_seconds:
        HTTP request timeout in seconds.

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    ip = (ip or "").strip()
    target_desc = "own public IP" if _is_self_lookup(ip) else ip
    logger.info("Starting IP lookup for: %s", target_desc)
    try:
        data = await _fetch_ip_data(ip, timeout_seconds, api_key)
        result = _format_ip_results(data, ip)
        logger.info("IP lookup complete for: %s", target_desc)
        return result
    except OSINTError as exc:
        logger.warning("IP lookup failed: %s", exc)
        return f"Scan error: {exc}"
    except Exception as exc:
        logger.exception("Unexpected error during IP lookup.")
        return f"Internal error: {exc}"
