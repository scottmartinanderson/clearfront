# clearfront/tools/search_maigret.py
"""
Maigret integration, broad username/identity discovery across 3,000+ sites.

Wraps the 'maigret' CLI (a large, sherlock-derived database) to enumerate
platforms where a username exists, and to extract profile details (IDs,
creation dates, location, follower counts) where a site exposes them.

This is the PRIMARY deep username-discovery pass; search_username (sherlock)
remains as a secondary, URL-verified pass with confidence tiers. Maigret reports
account *existence*, like sherlock it can produce false positives, so treat
high-stakes hits as leads to corroborate.

Returns a formatted string; never raises on failure.
"""

from __future__ import annotations

import logging
import re
import tempfile

from clearfront.tools.exceptions import OSINTError
from clearfront.utils import run_subprocess

logger = logging.getLogger(__name__)

_BINARY = "maigret"
_INSTALL_HINT = "Install it with: pip install maigret"
_DEFAULT_TIMEOUT = 100          # overall subprocess wall-clock budget (seconds)
_PER_SITE_TIMEOUT = "5"         # seconds per site request, passed to --timeout
_DEFAULT_TOP_SITES = 500        # sites scanned, ranked by popularity (DB has 3,000+)
_MAX_DETAILS = 3                # profile detail lines shown per hit

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# maigret prints found accounts as "[+] Site: https://url".
_HIT_RE = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://\S+)\s*$")
# detail lines look like "  ├─location: San Francisco" / "  └─created_at: ...".
_DETAIL_RE = re.compile(r"^\s*[├└]─\s*([A-Za-z0-9_]+):\s*(.+?)\s*$")

# Profile fields worth surfacing, in priority order.
_HIGH_VALUE_FIELDS = (
    "fullname", "username", "location", "created_at", "follower_count", "id",
)


async def _run_maigret(username: str, top_sites: int, timeout_seconds: int) -> str:
    """Execute maigret and return raw stdout.

    Like sherlock, maigret writes a report folder into its working directory, so
    we run it in a throwaway temp dir (we only consume stdout). --no-autoupdate
    avoids a database download on startup.
    """
    with tempfile.TemporaryDirectory(prefix="clearfront-maigret-") as workdir:
        result = await run_subprocess(
            binary=_BINARY,
            args=[
                username,
                "--top-sites", str(top_sites),
                "--timeout", _PER_SITE_TIMEOUT,
                "--no-color",
                "--no-progressbar",
                "--no-autoupdate",
            ],
            timeout_seconds=timeout_seconds,
            install_hint=_INSTALL_HINT,
            cwd=workdir,
        )
    return result.stdout


def _parse(raw: str) -> list[tuple[str, str, dict]]:
    """Return [(site, url, details)] from maigret stdout."""
    hits: list[tuple[str, str, dict]] = []
    current: tuple[str, str, dict] | None = None
    for line in _ANSI_RE.sub("", raw).splitlines():
        m = _HIT_RE.match(line)
        if m:
            site, url = m.group(1).strip(), m.group(2).strip()
            # The "[+] Using sites database: <path>" banner has no http URL and
            # is excluded by the regex, but guard the label defensively too.
            if site.lower().startswith("using sites database"):
                current = None
                continue
            current = (site, url, {})
            hits.append(current)
            continue
        if current is not None:
            d = _DETAIL_RE.match(line)
            if d:
                current[2][d.group(1).lower()] = d.group(2).strip()
    return hits


def _format(hits: list[tuple[str, str, dict]], username: str) -> str:
    if not hits:
        return f"No accounts found for username '{username}' across the Maigret database."

    lines = [f"Maigret found {len(hits)} account(s) for '{username}' (3,000+ site database):\n"]
    for site, url, details in hits:
        lines.append(f"[+] {site}: {url}")
        shown = [(k, details[k]) for k in _HIGH_VALUE_FIELDS if k in details]
        for k, v in shown[:_MAX_DETAILS]:
            lines.append(f"      {k}: {v}")
    lines.append(
        "\nSource: maigret (account-existence across 3,000+ sites). Some sites "
        "yield false positives, corroborate high-stakes findings."
    )
    return "\n".join(lines)


async def run_maigret_osint(
    username: str,
    top_sites: int = _DEFAULT_TOP_SITES,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Enumerate platforms where username exists via maigret (3,000+ sites).

    Parameters
    ----------
    username:
        The username/handle to search for.
    top_sites:
        How many sites to scan, ranked by popularity (the database has 3,000+).
    timeout_seconds:
        Hard wall-clock limit for the maigret subprocess.

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    username = username.strip()
    if not username:
        return "Invalid input: username must not be empty."
    if username.startswith("-"):
        return "Invalid input: username must not start with '-'."

    logger.info("Starting maigret search for: %s (top %d sites)", username, top_sites)
    try:
        raw = await _run_maigret(username, top_sites, timeout_seconds)
        hits = _parse(raw)
        logger.info("maigret search complete for: %s (%d hits)", username, len(hits))
        return _format(hits, username)
    except OSINTError as exc:
        logger.warning("maigret search failed: %s", exc)
        return f"Scan error: {exc}"
    except Exception as exc:  # noqa: BLE001, never crash the agent
        logger.exception("Unexpected error during maigret search.")
        return f"Internal error: {exc}"
