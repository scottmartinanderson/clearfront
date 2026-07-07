# clearfront/tools/search_username.py
"""
Username OSINT module.

Wraps the 'sherlock' binary to enumerate platforms where a username is
registered, then VERIFIES each candidate to filter false positives.

sherlock detects accounts by requesting a site's profile URL and inspecting the
response. Many sites return a valid page (HTTP 200) for *any* username, so
sherlock is prone to false positives. To pass accurate data downstream, this
module fetches every candidate URL and classifies it:

  CONFIRMED   - profile responded and the page references the username
  UNCONFIRMED - responded but the username could not be confirmed in the page
                (may be a real JS-rendered profile, or a false positive)
  ruled out   - 404/4xx, or redirected away from the profile URL

Returns a formatted string; never raises on failure.
"""

from __future__ import annotations

import asyncio
import logging
import re
import tempfile
from urllib.parse import urlparse

import aiohttp

from clearfront.tools.exceptions import OSINTError
from clearfront.tools.whatsmyname import run_whatsmyname_check
from clearfront.utils import run_subprocess

logger = logging.getLogger(__name__)

_BINARY = "sherlock"
_DEFAULT_TIMEOUT = 180
_INSTALL_HINT = "Install it with: pip install sherlock-project"
_PER_SITE_TIMEOUT = "5"  # seconds per site, passed to sherlock --timeout

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# sherlock prints found accounts as "[+] Site: https://url".
_HIT_RE = re.compile(r"^\[\+\]\s+(.+?):\s+(https?://\S+)\s*$")

# Verification tuning.
_VERIFY_CONCURRENCY = 20
_VERIFY_TIMEOUT = 8  # seconds per candidate URL
_VERIFY_CAP = 100  # max candidates to fetch (bounds wall-clock time)
_READ_BYTES = 80_000  # cap body read per candidate
_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

CONFIRMED, UNCONFIRMED, REJECTED = "confirmed", "unconfirmed", "rejected"


async def _run_sherlock(username: str, timeout_seconds: int) -> str:
    """Execute sherlock against username and return raw stdout.

    sherlock unconditionally saves a ``<username>.txt`` results file into its
    working directory. We only consume stdout, so run it in a throwaway temp
    dir to keep that artifact out of the repo (auto-removed on exit).
    """
    with tempfile.TemporaryDirectory(prefix="clearfront-sherlock-") as workdir:
        result = await run_subprocess(
            binary=_BINARY,
            args=[username, "--print-found", "--no-color", "--timeout", _PER_SITE_TIMEOUT],
            timeout_seconds=timeout_seconds,
            install_hint=_INSTALL_HINT,
            cwd=workdir,
        )
    return result.stdout


def _parse_sherlock(raw: str) -> list[tuple[str, str]]:
    """Return de-duplicated (site, url) candidate hits from sherlock stdout."""
    hits: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in _ANSI_RE.sub("", raw).splitlines():
        m = _HIT_RE.match(line.strip())
        if not m:
            continue
        site, url = m.group(1).strip(), m.group(2).strip()
        if url not in seen:
            seen.add(url)
            hits.append((site, url))
    return hits


def _classify(username: str, status: int, final_url: str, body: str) -> str:
    """Pure verdict for a fetched candidate.

    - 4xx/5xx                       -> REJECTED (profile does not exist)
    - redirected off the profile URL (username no longer in the final URL)
                                    -> REJECTED (site bounced an unknown user home)
    - username present in page body -> CONFIRMED
    - otherwise                     -> UNCONFIRMED (responded, unprovable)
    """
    if status >= 400:
        return REJECTED
    uname = username.lower()
    if uname not in final_url.lower().rstrip("/"):
        return REJECTED
    if uname in body.lower():
        return CONFIRMED
    return UNCONFIRMED


async def _verify_hits(username: str, hits: list[tuple[str, str]]) -> list[tuple[str, str, str]]:
    """Fetch candidate URLs concurrently and classify each. Network failures are
    treated as UNCONFIRMED (kept, not dropped). Candidates beyond the cap are
    returned UNCONFIRMED without a fetch."""
    to_check = hits[:_VERIFY_CAP]
    sem = asyncio.Semaphore(_VERIFY_CONCURRENCY)
    headers = {"User-Agent": _UA, "Accept-Language": "en-US,en;q=0.9"}
    timeout = aiohttp.ClientTimeout(total=_VERIFY_TIMEOUT)

    async def _one(session: aiohttp.ClientSession, site: str, url: str) -> tuple[str, str, str]:
        async with sem:
            try:
                async with session.get(url, allow_redirects=True) as resp:
                    chunk = await resp.content.read(_READ_BYTES)
                    body = chunk.decode("utf-8", errors="ignore")
                    verdict = _classify(username, resp.status, str(resp.url), body)
            except Exception:
                verdict = UNCONFIRMED  # could not verify - keep, do not claim found
            return (site, url, verdict)

    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        results = await asyncio.gather(*(_one(session, s, u) for s, u in to_check))

    out = list(results)
    out.extend((s, u, UNCONFIRMED) for s, u in hits[_VERIFY_CAP:])
    return out


def _format_verified(username: str, results: list[tuple[str, str, str]]) -> str:
    """Render verification results in confidence tiers."""
    confirmed = [(s, u) for s, u, v in results if v == CONFIRMED]
    unconfirmed = [(s, u) for s, u, v in results if v == UNCONFIRMED]
    rejected = sum(1 for *_, v in results if v == REJECTED)

    if not confirmed and not unconfirmed:
        return (
            f"No verified accounts found for username '{username}'. "
            f"{rejected} sherlock candidate(s) were checked and ruled out (404 / redirected away)."
        )

    lines = [f"Username '{username}' - verified account check:", ""]
    if confirmed:
        lines.append(f"CONFIRMED ({len(confirmed)}) - live profile that references the username:")
        lines += [f"[+] {s}: {u}" for s, u in confirmed]
        lines.append("")
    if unconfirmed:
        lines.append(
            f"UNCONFIRMED ({len(unconfirmed)}) - responded but the username could not be "
            "auto-confirmed; verify manually (may be a real JS-rendered profile or a false positive):"
        )
        lines += [f"[?] {s}: {u}" for s, u in unconfirmed]
        lines.append("")
    if rejected:
        lines.append(f"Ruled out: {rejected} sherlock candidate(s) (404 / redirected away).")
    return "\n".join(lines).rstrip()


def _host(url: str) -> str:
    """Lowercased host (www stripped) for cross-source dedupe."""
    try:
        h = urlparse(url).netloc.lower()
    except Exception:
        return url.lower()
    return h[4:] if h.startswith("www.") else h


async def _sherlock_pipeline(
    username: str, timeout_seconds: int
) -> tuple[list[tuple[str, str, str]], str | None]:
    """Run sherlock + verification. Returns (results, error_message_or_None)."""
    try:
        raw = await _run_sherlock(username, timeout_seconds)
    except OSINTError as exc:
        logger.warning("Username scan (sherlock) failed: %s", exc)
        return [], f"Scan error: {exc}"
    hits = _parse_sherlock(raw)
    if not hits:
        return [], None
    logger.info("Verifying %d sherlock candidate(s) for: %s", len(hits), username)
    return await _verify_hits(username, hits), None


async def run_username_osint(
    username: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Run a username OSINT scan and return a formatted, verified result string.

    Runs two sources concurrently: sherlock (each candidate verified by fetching
    its profile URL) and a bundled WhatsMyName subset (high-confidence matches via
    each site's exact detection string). Results merge into confidence tiers,
    deduped by host. Returns a descriptive error string on failure; never raises.

    Parameters
    ----------
    username:
        Target username or alias.
    timeout_seconds:
        Maximum execution time for the sherlock subprocess (verification and the
        WhatsMyName check have their own per-request timeouts on top of this).

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    if username.startswith("-"):
        return "Error: invalid username (must not start with '-')."
    logger.info("Starting username OSINT scan for: %s", username)
    try:
        (sher_results, sher_err), wmn_found = await asyncio.gather(
            _sherlock_pipeline(username, timeout_seconds),
            run_whatsmyname_check(username),
        )
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected error during username scan.")
        return f"Internal error: {exc}"

    # Merge WhatsMyName confirmations into the results, deduped by host so a site
    # sherlock already found is not listed twice. WhatsMyName matches are exact
    # (detection-string), so they enter the CONFIRMED tier.
    seen = {_host(u) for _, u, _ in sher_results}
    merged = list(sher_results)
    wmn_added = 0
    for name, url in wmn_found:
        if _host(url) not in seen:
            merged.append((name, url, CONFIRMED))
            seen.add(_host(url))
            wmn_added += 1

    if not merged:
        return sher_err or f"No accounts found for username '{username}'."

    result = _format_verified(username, merged)
    coverage = "sherlock (verified)"
    if wmn_found:
        coverage += f" + WhatsMyName ({wmn_added} additional site(s))"
    result += f"\n\nCoverage: {coverage}."
    logger.info("Username scan complete for: %s (+%d WhatsMyName)", username, wmn_added)
    return result
