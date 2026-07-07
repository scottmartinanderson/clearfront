# clearfront/tools/search_hudsonrock.py
"""
Hudson Rock (Cavalier) infostealer-exposure check.

Answers one defensive question: does an identifier appear in Hudson Rock's free
Cavalier infostealer database, i.e. credentials exfiltrated by malware from an
infected machine? For an email or username it reports WHETHER the identifier is
exposed and the infection metadata that drives remediation: how many stealer
infections, when, the infected machine's OS, whether antivirus was present, the
malware file name, and how many corporate/user services were caught in the logs.

AUTHORIZED-USE ONLY. This exists to check your own (or an identifier you are
authorized to assess) infostealer exposure so you can rotate credentials and clean
the infected device, not to harvest other people's data. Two hard guarantees keep
it on the defensive side of that line:

  1. It uses ONLY the free Cavalier endpoint. Hudson Rock already returns that tier
     with passwords, logins, and IPs masked; the plaintext lives behind their paid
     API, which this tool never touches. So it can never surface a working password
     or login URL.
  2. It goes one step further than Hudson Rock's free tier and never echoes even the
     masked credential fields (top_passwords / top_logins) or the identifying
     machine strings (computer_name, full malware path). The actionable finding is
     the exposure and its recency/blast-radius, not the credential material.

Keyless. Passive single-identifier lookup. Analyst-invoked, never auto-pivoted
(kept out of pivot._TOOL_ROUTES). Returns a formatted string; never raises.
"""

from __future__ import annotations

import asyncio
import logging
import re

import aiohttp

logger = logging.getLogger(__name__)

_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_DEFAULT_TIMEOUT = 30
_MAX_INFECTIONS_SHOWN = 5

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _looks_like_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value))


def _malware_filename(path: str) -> str:
    """Return just the executable name from a malware path.

    The full path routinely embeds the victim's Windows username
    (``C:\\Users\\alice\\...``); the file name alone is the useful IOC without the
    identifying directory.
    """
    if not path:
        return ""
    tail = re.split(r"[\\/]", str(path))[-1].strip()
    return tail[:80]


def _summarize_infection(stealer: dict, idx: int) -> str:
    date = str(stealer.get("date_compromised") or "unknown date").strip()
    os_name = str(stealer.get("operating_system") or "unknown OS").strip()
    av = stealer.get("antiviruses")
    if isinstance(av, list):
        av_text = ", ".join(str(a) for a in av) if av else "none detected"
    else:
        av_text = str(av) if av else "none detected"
    malware = _malware_filename(stealer.get("malware_path", ""))
    parts = [f"[Hudson Rock] Infection {idx}: compromised {date}; OS {os_name}; antivirus: {av_text}"]
    if malware:
        parts.append(f"; malware file: {malware}")
    return "".join(parts) + "."


def _format_response(target: str, data: object) -> str:
    """Format a Cavalier response into a defensive exposure summary.

    Pure and side-effect-free so the "never echo credential material" guarantee is
    directly testable. Only ever reads the exposure/infection metadata fields; it
    never reads ``top_passwords`` / ``top_logins`` / ``computer_name`` / the full
    ``malware_path``, so no credential or identifying machine string can reach the
    output regardless of what the API returns.
    """
    if not isinstance(data, dict):
        return f"[Hudson Rock] No usable data returned for {target}."

    stealers = data.get("stealers")
    stealers = stealers if isinstance(stealers, list) else []

    if not stealers:
        # Clean: not present in the infostealer index. Surface Hudson Rock's own
        # not-found message when it provides one.
        note = str(data.get("message") or "").strip()
        clean = f"[Hudson Rock] CLEAN: {target} was not found in the free infostealer index."
        return clean + (f" ({note})" if note else "") + (
            "\nSource: Hudson Rock Cavalier free infostealer index (passive)."
        )

    count = len(stealers)
    lines = [
        f"[RISK] [Hudson Rock] EXPOSED: {target} appears in infostealer data "
        f"({count} infection{'s' if count != 1 else ''} on record)."
    ]
    for i, stealer in enumerate(stealers[:_MAX_INFECTIONS_SHOWN], start=1):
        if isinstance(stealer, dict):
            lines.append(_summarize_infection(stealer, i))
    if count > _MAX_INFECTIONS_SHOWN:
        lines.append(f"[Hudson Rock] ... and {count - _MAX_INFECTIONS_SHOWN} more infection(s).")

    total_user = data.get("total_user_services")
    total_corp = data.get("total_corporate_services")
    if isinstance(total_user, int) or isinstance(total_corp, int):
        lines.append(
            f"[Hudson Rock] Services caught in these logs: "
            f"{total_user if isinstance(total_user, int) else 'n/a'} user, "
            f"{total_corp if isinstance(total_corp, int) else 'n/a'} corporate."
        )

    lines.append(
        "[Hudson Rock] Remediation: treat every credential entered on the affected machine(s) as "
        "compromised, rotate passwords and MFA, and ensure the infected device is cleaned."
    )
    lines.append(
        "Source: Hudson Rock Cavalier free infostealer index (passive, authorized-use). "
        "Credential values are intentionally not retrieved."
    )
    return "\n".join(lines)


async def run_hudsonrock_osint(target: str, timeout_seconds: int = _DEFAULT_TIMEOUT) -> str:
    """Check an email or username against Hudson Rock's free infostealer index."""
    target = (target or "").strip()
    if not target:
        return "Error: an email address or username is required for a Hudson Rock lookup."

    if _looks_like_email(target):
        url = f"{_BASE}/search-by-email"
        params = {"email": target}
    else:
        url = f"{_BASE}/search-by-username"
        params = {"username": target}

    timeout_cfg = aiohttp.ClientTimeout(total=timeout_seconds)
    headers = {"Accept": "application/json"}
    logger.info("Starting Hudson Rock infostealer lookup for: %s", target)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg, headers=headers) as session:
            async with session.get(url, params=params) as resp:
                if resp.status == 429:
                    return "[Hudson Rock] Rate limit reached on the free Cavalier API. Try later."
                if resp.status != 200:
                    return f"[Hudson Rock] Error: HTTP {resp.status} querying the Cavalier API."
                data = await resp.json(content_type=None)
    except asyncio.TimeoutError:
        return f"[Hudson Rock] Error: request timed out after {timeout_seconds}s."
    except aiohttp.ClientError as exc:
        return f"[Hudson Rock] Error: network error querying Hudson Rock: {exc}"
    except Exception as exc:  # noqa: BLE001, never crash the agent
        logger.exception("Unexpected error during Hudson Rock lookup.")
        return f"[Hudson Rock] Internal error: {exc}"

    return _format_response(target, data)
