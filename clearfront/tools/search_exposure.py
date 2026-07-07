# clearfront/tools/search_exposure.py
"""
IP self-exposure report.

Aggregates passive, public signals about an IP address into a single,
risk-ranked "what's exposed about you" report. With no IP (or "me"/"self"),
auto-detects the caller's own public IP so a user can check their own exposure
in one step.

Core signals (free, no key required):
  - ipinfo.io        : geolocation, ASN / organisation, reverse-DNS hostname
  - reverse DNS / PTR: full PTR record (can reveal ISP / employer / host identity)
  - DNS blocklists   : Spamhaus ZEN, SpamCop, Barracuda (spam / abuse reputation)

Optional enrichment (used only when the key is present):
  - IP2Location      : VPN / proxy / Tor / datacenter classification

Returns a formatted, risk-ranked string; never raises.
"""

from __future__ import annotations

import asyncio
import logging
import os

import dns.exception
import dns.resolver
import dns.reversename

from clearfront.tools.search_ip import _fetch_ip_data, _is_self_lookup
from clearfront.tools.search_ip2location import _fetch_ip2location_data

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 20
_DNS_TIMEOUT = 5.0

# IPv4 DNS blocklists: (query zone, human label).
_DNSBLS = [
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("b.barracudacentral.org", "Barracuda"),
]

# Severity ranks (lower sorts first).
_RISK, _WATCH, _INFO = 0, 1, 2


def _reverse_ptr(ip: str, timeout: float = _DNS_TIMEOUT) -> str | None:
    """Return the PTR (reverse-DNS) hostname for ip, or None on failure/none."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        answers = resolver.resolve(dns.reversename.from_address(ip), "PTR")
        return str(answers[0]).rstrip(".") if answers else None
    except Exception:
        return None


def _dnsbl_listings(ip: str, timeout: float = _DNS_TIMEOUT) -> list[str]:
    """Return the labels of DNS blocklists that currently list ip (IPv4 only)."""
    octets = ip.split(".")
    if len(octets) != 4 or not all(o.isdigit() for o in octets):
        return []  # IPv6 / malformed, these DNSBLs are IPv4-only
    reversed_ip = ".".join(reversed(octets))

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    listed: list[str] = []
    for zone, label in _DNSBLS:
        try:
            resolver.resolve(f"{reversed_ip}.{zone}", "A")
            listed.append(label)  # any A answer means the IP is listed
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass  # not listed by this provider
        except (dns.exception.DNSException, Exception):
            pass  # transient/resolver error, treat as "unknown", skip
    return listed


async def _ip2location_flags(ip: str, api_key: str, timeout: int) -> dict | None:
    """Return VPN/proxy/Tor/datacenter flags from IP2Location, or None on failure."""
    try:
        data = await _fetch_ip2location_data(ip, api_key, timeout)
    except Exception:
        return None
    proxy = data.get("proxy", {})
    if not isinstance(proxy, dict):
        proxy = {}
    return {
        "is_proxy": bool(proxy.get("is_proxy", data.get("is_proxy", False))),
        "is_vpn": bool(proxy.get("is_vpn", False)),
        "is_tor": bool(proxy.get("is_tor", False)),
        "is_datacenter": bool(proxy.get("is_datacenter", False)),
        "threat": proxy.get("threat") or "",
        "isp": data.get("isp", ""),
    }


def _format_report(
    resolved_ip: str,
    ipinfo: dict,
    ptr: str | None,
    dnsbls: list[str],
    ip2l: dict | None,
    is_self: bool,
) -> str:
    """Assemble the risk-ranked report from the collected signals."""
    findings: list[tuple[int, str]] = []

    if dnsbls:
        findings.append((
            _RISK,
            f"[RISK] Listed on {len(dnsbls)} DNS blocklist(s): {', '.join(dnsbls)}. "
            "Poor IP reputation, outbound mail may be blocked, and it can indicate prior "
            "abuse or a compromised host. Request delisting / check for compromise.",
        ))

    hostname = ptr or ipinfo.get("hostname")
    if hostname:
        findings.append((
            _WATCH,
            f"[WATCH] Reverse-DNS resolves to '{hostname}'. This can reveal your ISP, "
            "employer, or a self-hosted service tied to you.",
        ))

    if ip2l:
        if ip2l["is_tor"]:
            findings.append((_WATCH, "[WATCH] Flagged as a Tor exit node."))
        if ip2l["is_vpn"] or ip2l["is_proxy"]:
            findings.append((
                _INFO,
                "[INFO] Flagged as VPN/proxy, shared IP; your real location is likely masked.",
            ))
        if ip2l["is_datacenter"]:
            findings.append((_INFO, "[INFO] Hosted in a datacenter (non-residential)."))
        if ip2l.get("threat"):
            findings.append((_WATCH, f"[WATCH] IP2Location threat classification: {ip2l['threat']}."))

    loc_bits = [b for b in (ipinfo.get("city"), ipinfo.get("region"), ipinfo.get("country")) if b]
    if loc_bits:
        coords = ipinfo.get("loc")
        suffix = f" (Loc: {coords})" if coords else ""
        findings.append(
            (_INFO, f"[INFO] Approx. location visible to anyone: {', '.join(loc_bits)}.{suffix}")
        )
    org = ipinfo.get("org")
    if org:
        findings.append((_INFO, f"[INFO] Network / owner: {org}."))
    isp = (ip2l or {}).get("isp")
    if isp and isp != org:
        findings.append((_INFO, f"[INFO] ISP: {isp}."))

    findings.sort(key=lambda f: f[0])
    risk_count = sum(1 for sev, _ in findings if sev == _RISK)
    watch_count = sum(1 for sev, _ in findings if sev == _WATCH)

    header = f"Exposure report for {resolved_ip}"
    if is_self:
        header += " (your public IP)"

    lines = [header, f"{risk_count} risk(s), {watch_count} item(s) to watch.", ""]
    lines += [text for _, text in findings]
    if is_self:
        lines += [
            "",
            "[i] This reflects the IP the internet currently sees you as. On a VPN/proxy this "
            "is the exit IP, not your home address, for real-IP leakage, run a WebRTC/DNS leak test.",
        ]
    return "\n".join(lines)


async def run_exposure_osint(ip: str = "", timeout_seconds: int = _DEFAULT_TIMEOUT) -> str:
    """
    Produce a risk-ranked exposure report for ip.

    If ip is empty (or "me"/"self"), auto-detect the caller's own public IP.
    Aggregates ipinfo geolocation/ASN/hostname, reverse-DNS/PTR, DNS-blocklist
    membership, and (when ``IP2LOCATION_API_KEY`` is set) VPN/proxy/Tor/datacenter
    classification. Returns a descriptive error string on failure rather than raising.
    """
    ip = (ip or "").strip()
    is_self = _is_self_lookup(ip)
    logger.info("Starting exposure report for: %s", "own public IP" if is_self else ip)

    try:
        ipinfo = await _fetch_ip_data("" if is_self else ip, timeout_seconds)
    except Exception as exc:
        return f"Scan error: could not look up the IP via ipinfo.io: {exc}"

    if "bogon" in ipinfo:
        disp = ipinfo.get("ip") or ip or "that address"
        return f"'{disp}' is a private/bogon address, no public exposure data available."

    resolved_ip = ipinfo.get("ip") or ip
    if not resolved_ip:
        return "Scan error: could not determine the target IP address."

    ptr, dnsbls = await asyncio.gather(
        asyncio.to_thread(_reverse_ptr, resolved_ip),
        asyncio.to_thread(_dnsbl_listings, resolved_ip),
    )

    ip2l = None
    ip2l_key = os.environ.get("IP2LOCATION_API_KEY", "").strip()
    if ip2l_key:
        ip2l = await _ip2location_flags(resolved_ip, ip2l_key, timeout_seconds)

    result = _format_report(resolved_ip, ipinfo, ptr, dnsbls, ip2l, is_self)
    logger.info("Exposure report complete for: %s", resolved_ip)
    return result
