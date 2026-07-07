# clearfront/tools/search_ip2location.py
"""
IP2Location integration module.

Queries the IP2Location.io API for enhanced IP intelligence including
geolocation, ISP, ASN, and detection of VPN, proxy, Tor exit nodes,
and datacenter hosting.

Requires IP2LOCATION_API_KEY environment variable.
Sponsored integration.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re

import aiohttp

from clearfront.tools.exceptions import OSINTError, ToolExecutionError

logger = logging.getLogger(__name__)

_API_URL = "https://api.ip2location.io/"
_DEFAULT_TIMEOUT = 30

_IP_RE = re.compile(
    r"^("
    r"(\d{1,3}\.){3}\d{1,3}"  # IPv4
    r"|"
    r"([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}"  # IPv6 (simplified)
    r")$"
)


def _is_valid_ip(ip: str) -> bool:
    return bool(_IP_RE.match(ip.strip()))


async def _fetch_ip2location_data(ip: str, api_key: str, timeout: int) -> dict:
    """Query the IP2Location.io API (async, non-blocking)."""
    params = {"key": api_key, "ip": ip, "format": "json"}
    timeout_cfg = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            async with session.get(_API_URL, params=params) as resp:
                if resp.status == 400:
                    raise OSINTError("IP2Location: invalid request or API key.")
                if resp.status == 401:
                    raise OSINTError("IP2Location: invalid API key.")
                if resp.status == 429:
                    raise OSINTError("IP2Location: rate limit exceeded.")
                if resp.status != 200:
                    raise ToolExecutionError(f"IP2Location returned HTTP {resp.status}.")
                return await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        raise OSINTError(f"Network error querying IP2Location: {exc}") from exc


def _format_ip2location_results(data: dict, ip: str) -> str:
    lines = [
        f"[IP2Location] IP: {data.get('ip', ip)}",
    ]

    country_name = data.get("country_name", "")
    country_code = data.get("country_code", "")
    if country_name:
        country_display = f"{country_name} ({country_code})" if country_code else country_name
        lines.append(f"[IP2Location] Country: {country_display}")

    region = data.get("region_name", "")
    if region:
        lines.append(f"[IP2Location] Region: {region}")

    city = data.get("city_name", "")
    if city:
        lines.append(f"[IP2Location] City: {city}")

    lat = data.get("latitude", "")
    if lat != "":
        lines.append(f"[IP2Location] Latitude: {lat}")

    lon = data.get("longitude", "")
    if lon != "":
        lines.append(f"[IP2Location] Longitude: {lon}")

    zip_code = data.get("zip_code", "")
    if zip_code:
        lines.append(f"[IP2Location] ZIP: {zip_code}")

    isp = data.get("isp", "")
    if isp:
        lines.append(f"[IP2Location] ISP: {isp}")

    domain = data.get("domain", "")
    if domain:
        lines.append(f"[IP2Location] Domain: {domain}")

    asn = data.get("as", "")
    if asn:
        lines.append(f"[IP2Location] ASN: {asn}")

    # Proxy/VPN/Tor/Datacenter detection from the Security Plan
    proxy_data = data.get("is_proxy", None)
    vpn_data = data.get("proxy", {})

    is_proxy = False
    is_vpn = False
    is_tor = False
    is_datacenter = False
    threat = "clean"

    if isinstance(vpn_data, dict):
        is_proxy = bool(vpn_data.get("is_proxy", False))
        is_vpn = bool(vpn_data.get("is_vpn", False))
        is_tor = bool(vpn_data.get("is_tor", False))
        is_datacenter = bool(vpn_data.get("is_datacenter", False))
        threat = vpn_data.get("threat", "clean") or "clean"
    elif proxy_data is not None:
        is_proxy = bool(proxy_data)

    lines.append(f"[IP2Location] Proxy: {'Yes' if is_proxy else 'No'}")
    lines.append(f"[IP2Location] VPN: {'Yes' if is_vpn else 'No'}")
    lines.append(f"[IP2Location] TOR: {'Yes' if is_tor else 'No'}")
    lines.append(f"[IP2Location] Datacenter: {'Yes' if is_datacenter else 'No'}")
    lines.append(f"[IP2Location] Threat: {threat}")

    if is_proxy or is_vpn or is_tor:
        lines.append("⚠️  FLAGGED: VPN/Proxy/Tor detected")

    return "\n".join(lines)


async def run_ip2location_osint(
    ip: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
    *,
    api_key: str | None = None,
) -> str:
    """
    Retrieve enhanced IP intelligence via the IP2Location.io API.

    Returns geolocation, ISP, ASN, and detects VPN, proxy, Tor exit nodes,
    and datacenter hosting. Sponsored integration.

    Requires ``IP2LOCATION_API_KEY`` environment variable.

    Returns
    -------
    str
        Formatted result string or descriptive error message.
    """
    resolved_key = api_key or os.environ.get("IP2LOCATION_API_KEY", "")
    if not resolved_key:
        return (
            "Scan error: IP2LOCATION_API_KEY environment variable is not set. "
            "Get a key at https://www.ip2location.io/pricing"
        )

    ip = ip.strip()
    if not _is_valid_ip(ip):
        return "Invalid IP address format."

    logger.info("Starting IP2Location lookup for: %s", ip)
    try:
        data = await _fetch_ip2location_data(ip, resolved_key, timeout_seconds)
        result = _format_ip2location_results(data, ip)
        logger.info("IP2Location lookup complete for: %s", ip)
        return result
    except OSINTError as exc:
        logger.warning("IP2Location lookup failed: %s", exc)
        return f"Scan error: {exc}"
    except Exception as exc:
        logger.exception("Unexpected error during IP2Location lookup.")
        return f"Internal error: {exc}"
