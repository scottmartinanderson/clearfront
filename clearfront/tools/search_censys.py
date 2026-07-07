# clearfront/tools/search_censys.py
"""
Censys integration module (Censys Platform API).

Queries the Censys Platform API for internet-facing infrastructure data.
Auto-detects whether the input is an IPv4 address or a domain name.

  - IP address  → global_data.get_host(ip) , open ports, services, ASN, location
  - Domain      → global_data.search('cert.names: "<domain>"'), certificate history

Authentication uses a Censys Platform **Personal Access Token** (the legacy API
ID/Secret pair was deprecated; legacy Search is retired Sept 2026). Set:

  - ``CENSYS_PAT``      , Personal Access Token (falls back to ``CENSYS_SECRET``
                           for backwards compatibility, since a PAT may already be
                           stored there). The token implies its organization, so
                           lookups work with the PAT alone.
  - ``CENSYS_ORG_ID``   , Organization ID. **Optional**, only needed to target a
                           specific org on a multi-org account; omit otherwise.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re

from clearfront.tools.exceptions import OSINTError

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30
_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_MAX_CERTS = 50
_GET_TOKENS_URL = "https://platform.censys.io (Personal Access Tokens page)"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_ip_address(target: str) -> bool:
    """Return True when target looks like an IPv4 address."""
    return bool(_IP_RE.match(target.strip()))


def _credentials() -> tuple[str, str]:
    """Return (personal_access_token, organization_id) from the environment.

    The PAT may live under ``CENSYS_PAT`` or, for backwards compatibility, the
    older ``CENSYS_SECRET`` slot. The org id is optional (empty == infer from
    the token).
    """
    pat = os.environ.get("CENSYS_PAT", "") or os.environ.get("CENSYS_SECRET", "")
    org = os.environ.get("CENSYS_ORG_ID", "")
    return pat.strip(), org.strip()


def _sdk_kwargs(pat: str, org: str) -> dict:
    """Build SDK constructor kwargs, including org id only when provided."""
    kwargs = {"personal_access_token": pat}
    if org:
        kwargs["organization_id"] = org
    return kwargs


def _format_ip_result(host: dict, ip: str) -> str:
    """Format a Platform host record (dict from Host.model_dump())."""
    lines = ["[Censys] Type: ip", f"[Censys] IP: {host.get('ip') or ip}"]

    services = host.get("services") or []
    ports = sorted(
        {str(s.get("port")) for s in services if s.get("port")},
        key=lambda p: int(p) if p.isdigit() else 0,
    )
    if ports:
        lines.append(f"[Censys] Open Ports: {', '.join(ports[:20])}")

    svc_names: list[str] = []
    seen: set[str] = set()
    for s in services:
        name = s.get("protocol") or s.get("extended_service_name") or ""
        if name and name not in seen:
            seen.add(name)
            svc_names.append(name)
    if svc_names:
        lines.append(f"[Censys] Services: {', '.join(svc_names[:20])}")

    asn_data = host.get("autonomous_system") or {}
    asn = asn_data.get("asn", "")
    asn_name = asn_data.get("name", "") or asn_data.get("organization", "")
    if asn:
        lines.append(f"[Censys] ASN: AS{asn} {asn_name}".rstrip())

    location = host.get("location") or {}
    country = location.get("country", "")
    if country:
        lines.append(f"[Censys] Country: {country}")

    return "\n".join(lines)


def _format_domain_result(certs: list[dict], domain: str) -> str:
    """Format a list of Platform certificate records (Certificate.model_dump())."""
    lines = [
        "[Censys] Type: domain",
        f"[Censys] Domain: {domain}",
        f"[Censys] Certificates Found: {len(certs)}",
    ]
    if not certs:
        return "\n".join(lines)

    first = certs[0]
    parsed = first.get("parsed") or {}

    issuer = parsed.get("issuer") or {}
    issuer_orgs = issuer.get("organization")
    issuer_name = ""
    if isinstance(issuer_orgs, list) and issuer_orgs:
        issuer_name = issuer_orgs[0]
    elif isinstance(issuer_orgs, str) and issuer_orgs:
        issuer_name = issuer_orgs
    else:
        issuer_name = issuer.get("common_name", "")
    if issuer_name:
        lines.append(f"[Censys] Issuer: {issuer_name}")

    names: list[str] = []
    seen: set[str] = set()
    for c in certs:
        for n in c.get("names") or []:
            if n not in seen:
                seen.add(n)
                names.append(n)
    if names:
        lines.append(f"[Censys] SANs: {', '.join(names[:10])}")

    starts: list[str] = []
    ends: list[str] = []
    for c in certs:
        validity = (c.get("parsed") or {}).get("validity_period") or {}
        if validity.get("not_before"):
            starts.append(validity["not_before"])
        if validity.get("not_after"):
            ends.append(validity["not_after"])
    if starts:
        lines.append(f"[Censys] First Seen: {min(starts)[:10]}")
    if ends:
        lines.append(f"[Censys] Last Seen: {max(ends)[:10]}")

    return "\n".join(lines)


def _dump(obj) -> dict:
    """Best-effort convert an SDK model (pydantic v2) or dict to a plain dict."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "model_dump"):
        return obj.model_dump(exclude_none=True)
    return dict(getattr(obj, "__dict__", {}) or {})


# ---------------------------------------------------------------------------
# Platform API calls (synchronous SDK, run off-thread by callers)
# ---------------------------------------------------------------------------


def _lookup_ip(pat: str, org: str, ip: str) -> str:
    from censys_platform import SDK  # type: ignore

    with SDK(**_sdk_kwargs(pat, org)) as sdk:
        resp = sdk.global_data.get_host(host_id=ip)
    host = _dump(getattr(getattr(resp, "result", None), "result", None)).get("resource")
    if not host:
        return f"No Censys data found for {ip}."
    return _format_ip_result(_dump(host), ip)


def _lookup_domain(pat: str, org: str, domain: str) -> str:
    from censys_platform import SDK  # type: ignore
    from censys_platform import SearchQueryInputBody  # type: ignore

    body = SearchQueryInputBody(query=f'cert.names: "{domain}"', page_size=_MAX_CERTS)
    with SDK(**_sdk_kwargs(pat, org)) as sdk:
        resp = sdk.global_data.search(search_query_input_body=body)
    hits = _dump(getattr(getattr(resp, "result", None), "result", None)).get("hits") or []
    certs: list[dict] = []
    for hit in hits:
        hit_d = _dump(hit)
        cert_asset = hit_d.get("certificate_v1")
        resource = _dump(cert_asset).get("resource") if cert_asset else None
        if resource:
            certs.append(_dump(resource))
    return _format_domain_result(certs, domain)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def run_censys_osint(target: str, timeout_seconds: int = _DEFAULT_TIMEOUT) -> str:
    """
    Run a Censys Platform lookup for *target*.

    Auto-detects input type: IPv4 address → host view (open ports, services,
    ASN, location); domain → certificate search (SANs, issuer, validity dates).

    Requires ``CENSYS_PAT`` (or legacy ``CENSYS_SECRET``). ``CENSYS_ORG_ID`` is
    optional, the token implies its organization.

    Returns
    -------
    str
        Formatted result string or descriptive error message.
    """
    pat, org = _credentials()
    if not pat:
        return (
            "Scan error: no Censys Personal Access Token set. "
            f"Set CENSYS_PAT (create one at {_GET_TOKENS_URL})."
        )

    try:
        import censys_platform  # type: ignore  # noqa: F401
    except ImportError:
        return (
            "Scan error: 'censys-platform' library is not installed. "
            "Install it with: pip install censys-platform"
        )

    target = target.strip()
    logger.info("Starting Censys Platform lookup for: %s", target)

    try:
        worker = _lookup_ip if _is_ip_address(target) else _lookup_domain
        result = await asyncio.wait_for(
            asyncio.to_thread(worker, pat, org, target),
            timeout=float(timeout_seconds),
        )
        logger.info("Censys lookup complete for: %s", target)
        return result

    except asyncio.TimeoutError:
        return f"Scan error: Censys request timed out after {timeout_seconds}s."
    except OSINTError as exc:
        logger.warning("Censys lookup failed: %s", exc)
        return f"Scan error: {exc}"
    except Exception as exc:
        exc_str = str(exc).lower()
        # Free-plan search restriction: the certificate/search API is paid-only.
        # Censys returns this for domain lookups on a free account.
        if "free users" in exc_str or "requires an organization id" in exc_str:
            return (
                "Censys domain/certificate search requires a paid Censys plan "
                "(free accounts can run IP host lookups via the API, but search "
                "only through the Platform web UI). Try an IP address instead."
            )
        if "rate" in exc_str or "429" in exc_str:
            return "Censys rate limit reached. Try again later."
        if "not found" in exc_str or "404" in exc_str:
            return "No Censys data found for target."
        if any(t in exc_str for t in ("401", "403", "unauthorized", "forbidden", "authentication")):
            return "Censys authentication failed. Check your CENSYS_PAT."
        logger.exception("Unexpected error during Censys lookup.")
        return f"Internal error: {exc}"
