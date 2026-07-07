# clearfront/tools/search_crt.py
"""
Certificate Transparency (crt.sh) OSINT module.

Queries the public crt.sh certificate-transparency log for certificates issued
to a domain and its subdomains. Purely passive (reads public CA logs, never
touches the target) and keyless, so it fits the free tier and the authorized,
public-source posture. It surfaces subdomains, including internal/staging hosts
that never resolve publicly, which sublist3r's brute force cannot.

crt.sh is a shared community resource that is often slow or returns 502 under
load, so the tool sets a descriptive User-Agent and degrades gracefully to an
"unavailable" message rather than raising. Returns a formatted string.
"""

from __future__ import annotations

import asyncio
import logging

import aiohttp

logger = logging.getLogger(__name__)

_CRT_URL = "https://crt.sh/"
_DEFAULT_TIMEOUT = 30
_MAX_SUBDOMAINS = 100
_HEADERS = {
    "User-Agent": "CLEARFRONT-OSINT (+https://github.com/scottmartinanderson/clearfront)"
}


def _clean_domain(target: str) -> str:
    """Normalise a target into a bare registrable domain."""
    t = (target or "").strip().lower()
    t = t.replace("https://", "").replace("http://", "").split("/")[0]
    return t.lstrip("*.").strip(".")


def _extract_subdomains(records: list, domain: str) -> list[str]:
    """Collect unique hostnames under *domain* from crt.sh certificate records."""
    found: set[str] = set()
    suffix = "." + domain
    for rec in records:
        if not isinstance(rec, dict):
            continue
        names = str(rec.get("name_value", "")).split("\n")
        cn = rec.get("common_name")
        if cn:
            names.append(str(cn))
        for name in names:
            host = name.strip().lower().lstrip("*.")
            if not host or "@" in host:
                continue
            if host == domain or host.endswith(suffix):
                found.add(host)
    return sorted(found)


async def run_crt_osint(domain: str, timeout_seconds: int = _DEFAULT_TIMEOUT) -> str:
    """
    Enumerate subdomains from certificate transparency via crt.sh.

    Parameters
    ----------
    domain:
        Target domain (e.g. example.com).
    timeout_seconds:
        Hard HTTP timeout; crt.sh can be slow.

    Returns
    -------
    str
        Formatted subdomain list, or a descriptive unavailable/error message.
    """
    domain = _clean_domain(domain)
    if not domain or "." not in domain:
        return "Error: a valid domain is required for a crt.sh lookup."

    params = {"q": f"%.{domain}", "output": "json"}
    timeout_cfg = aiohttp.ClientTimeout(total=timeout_seconds)
    logger.info("Starting crt.sh lookup for: %s", domain)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg, headers=_HEADERS) as session:
            async with session.get(_CRT_URL, params=params) as resp:
                if resp.status in (429, 502, 503, 504):
                    return (
                        f"[crt.sh] Unavailable: certificate-transparency service returned "
                        f"HTTP {resp.status} (crt.sh is frequently overloaded). Try again shortly."
                    )
                if resp.status != 200:
                    return f"[crt.sh] Error: HTTP {resp.status} querying crt.sh."
                try:
                    records = await resp.json(content_type=None)
                except Exception:
                    return (
                        "[crt.sh] Unavailable: crt.sh returned a non-JSON response "
                        "(usually an overload page). Try again shortly."
                    )
    except asyncio.TimeoutError:
        return (
            f"[crt.sh] Unavailable: request timed out after {timeout_seconds}s "
            "(crt.sh is frequently slow)."
        )
    except aiohttp.ClientError as exc:
        return f"[crt.sh] Error: network error querying crt.sh: {exc}"
    except Exception as exc:  # noqa: BLE001, never crash the agent
        logger.exception("Unexpected error during crt.sh lookup.")
        return f"[crt.sh] Internal error: {exc}"

    if not isinstance(records, list) or not records:
        return f"[crt.sh] No certificate-transparency records found for '{domain}'."

    subs = _extract_subdomains(records, domain)
    if not subs:
        return f"[crt.sh] No subdomains found in certificate transparency for '{domain}'."

    shown = subs[:_MAX_SUBDOMAINS]
    header = f"[crt.sh] {len(subs)} unique subdomain(s) in certificate transparency for '{domain}'"
    if len(subs) > _MAX_SUBDOMAINS:
        header += f" (showing first {_MAX_SUBDOMAINS})"
    lines = [header + ":"]
    lines.extend(f"[crt.sh] Subdomain: {s}" for s in shown)
    lines.append(
        "Source: crt.sh certificate transparency (public CA logs, passive). "
        "May include hosts that no longer resolve."
    )
    return "\n".join(lines)
