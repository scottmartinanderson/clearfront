# clearfront/tools/search_email.py
"""
Email OSINT module.

Wraps the 'holehe' binary to enumerate online services registered against a
target email address.

holehe always prints an author banner (Twitter / GitHub / BTC donation address)
before AND after its results, and by default emits an ANSI screen-clear
sequence. This module parses holehe's stdout down to the genuine hits
("[+] <domain>") and discards the banner, ANSI control codes, the legend, and
the summary line, so callers never see holehe's promotional noise.
Returns a formatted string; never raises on failure.
"""

from __future__ import annotations

import logging
import re

from clearfront.tools.exceptions import OSINTError, ToolExecutionError
from clearfront.utils import run_subprocess

logger = logging.getLogger(__name__)

_BINARY = "holehe"
_DEFAULT_TIMEOUT = 120
_INSTALL_HINT = "Install it with: pip install holehe"

# Any ANSI/CSI escape sequence (covers the "\x1b[H\x1b[J" screen-clear and colours).
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# A genuine hit is "[+] domain.tld". The legend "[+] Email used, [-] ..." has no
# domain token immediately after "[+]" and is therefore not matched.
_HIT_RE = re.compile(r"^\[\+\]\s+([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b", re.IGNORECASE)


async def _run_holehe(email: str, timeout_seconds: int) -> str:
    """Execute holehe against email and return raw stdout."""
    result = await run_subprocess(
        binary=_BINARY,
        # --only-used: only registered sites; --no-clear: drop the ANSI screen
        # wipe; --no-color: drop colour codes.
        args=[email, "--only-used", "--no-color", "--no-clear"],
        timeout_seconds=timeout_seconds,
        install_hint=_INSTALL_HINT,
    )
    if result.return_code != 0:
        raise ToolExecutionError(f"holehe exited with code {result.return_code}: {result.stderr}")
    return result.stdout


def _parse_holehe(raw: str) -> list[str]:
    """Return the de-duplicated services the email is registered on.

    Discards holehe's banner, ANSI control codes, the asterisk box, the legend
    line, and the summary line.
    """
    sites: list[str] = []
    seen: set[str] = set()
    for line in _ANSI_RE.sub("", raw).splitlines():
        m = _HIT_RE.match(line.strip())
        if not m:
            continue
        site = m.group(1).lower()
        if site not in seen:
            seen.add(site)
            sites.append(site)
    return sites


def _format_email_results(raw: str, email: str) -> str:
    """Return a clean, structured summary of holehe's findings."""
    sites = _parse_holehe(raw)
    if not sites:
        return f"No registered online services found for {email}."
    lines = [f"Email '{email}' appears registered on {len(sites)} service(s):", ""]
    lines += [f"[+] {s}" for s in sites]
    lines += [
        "",
        "Source: holehe (account-existence / password-reset endpoint checks). "
        "Treat these as leads, not proof - verify before relying on them.",
    ]
    return "\n".join(lines)


async def run_email_osint(
    email: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Run an email OSINT scan and return a formatted result string.

    Calls holehe to enumerate online services registered against the target
    email, then parses out holehe's banner/ANSI noise. Returns a descriptive
    error string on failure rather than raising.

    Parameters
    ----------
    email:
        Target email address.
    timeout_seconds:
        Maximum execution time for the holehe subprocess.

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    if email.startswith("-"):
        return "Error: invalid email address (must not start with '-')."
    logger.info("Starting email OSINT scan for: %s", email)
    try:
        raw = await _run_holehe(email, timeout_seconds)
        result = _format_email_results(raw, email)
        logger.info("Email scan complete for: %s", email)
        return result
    except OSINTError as exc:
        logger.warning("Email scan failed: %s", exc)
        return f"Scan error: {exc}"
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected error during email scan.")
        return f"Internal error: {exc}"
