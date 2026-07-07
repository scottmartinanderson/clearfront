# clearfront/tools/search_harvester.py
"""
Organisation/domain exposure module (theHarvester).

Wraps the 'theHarvester' binary to gather PASSIVE open-source intelligence on a
domain: email addresses, employee/people names, and subdomains/hosts aggregated
from public sources (certificate transparency, search engines, DNS datasets).

Scoped deliberately to passive collection for authorized organisation-exposure
self-checks: a curated set of keyless passive sources only, never active DNS
brute-force, port scanning, takeover checks, or screenshots. The API-key file is
skipped entirely (-q), so it runs keyless and never touches paid sources.

Surfaces emails and people first (the identity pivots), with subdomains/hosts as
bounded context. Returns a formatted string; never raises on failure.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile

from clearfront.tools.exceptions import OSINTError
from clearfront.utils import run_subprocess

logger = logging.getLogger(__name__)

_BINARY = "theHarvester"
_DEFAULT_TIMEOUT = 180
_INSTALL_HINT = "Install it with: pip install git+https://github.com/laramies/theHarvester.git"

# Curated PASSIVE, keyless sources only (no active brute-force, no paid keys).
# cert transparency + DNS datasets (subdomains) and search engines (emails).
_PASSIVE_SOURCES = (
    "crtsh,certspotter,rapiddns,hackertarget,otx,subdomaincenter,"
    "subdomainfinderc99,threatcrowd,urlscan,duckduckgo,brave,mojeek,yahoo"
)
_HOST_CAP = 40
_EMAIL_CAP = 60
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_-]{1,63}\.)+[a-zA-Z]{2,}$")


def _is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value.strip()))


def _clean_host(raw: str) -> str:
    """Reduce a theHarvester host entry ('sub.dom:1.2.3.4') to its hostname."""
    return raw.split(":")[0].strip().lower()


async def _run_harvester(domain: str, stem: str, timeout_seconds: int):
    """Run theHarvester (passive sources, keyless) writing JSON/XML to `stem`."""
    return await run_subprocess(
        binary=_BINARY,
        # -b passive sources, -f output stem, -l result cap, -q skip api-keys file.
        # No -c/-n/-r/-s/-t: strictly passive, no active probing.
        args=["-d", domain, "-b", _PASSIVE_SOURCES, "-f", stem, "-l", "100", "-q"],
        timeout_seconds=timeout_seconds,
        install_hint=_INSTALL_HINT,
    )


def _format_harvester(data: dict, domain: str) -> str:
    """Render theHarvester JSON, emails/people first, hosts as bounded context."""
    emails = sorted({e.strip().lower() for e in data.get("emails", []) if e and "@" in e})
    people: list[str] = []
    for key in ("linkedin_people", "twitter_people", "people"):
        people += [p for p in (data.get(key) or []) if p]
    hosts = sorted({_clean_host(h) for h in (data.get("hosts") or []) if h and "." in h})

    if not emails and not people and not hosts:
        return f"No passive OSINT found for domain '{domain}'."

    lines = [f"Passive domain recon for '{domain}':", ""]
    if emails:
        shown = emails[:_EMAIL_CAP]
        lines.append(f"Emails ({len(emails)}):")
        lines += [f"[+] {e}" for e in shown]
        if len(emails) > len(shown):
            lines.append(f"... and {len(emails) - len(shown)} more.")
        lines.append("")
    if people:
        lines.append(f"People ({len(people)}):")
        lines += [f"[+] {p}" for p in people[:40]]
        lines.append("")
    if hosts:
        shown_h = hosts[:_HOST_CAP]
        more = len(hosts) - len(shown_h)
        suffix = f", showing first {_HOST_CAP}" if more > 0 else ""
        lines.append(f"Subdomains/hosts ({len(hosts)}{suffix}):")
        lines += [f"[+] {h}" for h in shown_h]
        if more > 0:
            lines.append(f"... and {more} more.")
        lines.append("")
    lines.append(
        "Source: theHarvester passive sources (cert transparency, search engines, "
        "DNS datasets). Emails and hosts are leads; verify before relying on them."
    )
    return "\n".join(lines).rstrip()


async def run_harvester_osint(
    domain: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Gather passive OSINT (emails, people, subdomains) for a domain via theHarvester.

    Returns a descriptive error string on failure rather than raising.

    Parameters
    ----------
    domain:
        Target domain, e.g. example.com.
    timeout_seconds:
        Maximum execution time for the theHarvester subprocess.

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    domain = (domain or "").strip().lower()
    if not _is_domain(domain):
        return "Error: a valid domain is required (e.g. example.com)."
    logger.info("Starting theHarvester passive recon for: %s", domain)
    try:
        with tempfile.TemporaryDirectory(prefix="clearfront-harvester-") as workdir:
            stem = os.path.join(workdir, "out")
            await _run_harvester(domain, stem, timeout_seconds)
            json_path = stem + ".json"
            if not os.path.exists(json_path):
                return f"theHarvester returned no results for '{domain}'."
            with open(json_path, encoding="utf-8") as fh:
                data = json.load(fh)
        return _format_harvester(data, domain)
    except OSINTError as exc:
        logger.warning("theHarvester recon failed: %s", exc)
        return f"Scan error: {exc}"
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected error during theHarvester recon.")
        return f"Internal error: {exc}"
