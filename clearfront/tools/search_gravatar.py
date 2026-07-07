# clearfront/tools/search_gravatar.py
"""
Gravatar OSINT module.

Looks up an email address's PUBLIC Gravatar profile. Gravatar keys a profile to
the MD5 hash of the lowercased, trimmed email, so an avatar or profile only
exists if the person registered that email with Gravatar and made it public.

A public profile commonly exposes a display name, "about me" text, location,
pronouns/job, and a list of linked/verified social accounts and URLs, high-value
footprint pivots that tie an email to a real name and other accounts.

Keyless and fully public (the legacy profile JSON + avatar endpoints). When no
public profile exists it falls back to an avatar-existence check, which still
reveals whether the email is registered with Gravatar. Returns a formatted
string; never raises.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging

import aiohttp

from clearfront.tools.exceptions import OSINTError, ToolExecutionError

logger = logging.getLogger(__name__)

_PROFILE_URL = "https://gravatar.com/{hash}.json"
# d=404 → the avatar endpoint 404s instead of serving a default, so a 200 means
# the email has a real custom Gravatar avatar (i.e. it is registered).
_AVATAR_URL = "https://gravatar.com/avatar/{hash}?d=404&s=80"
_PROFILE_LINK = "https://gravatar.com/{hash}"
_DEFAULT_TIMEOUT = 10
# Gravatar rejects requests without a User-Agent.
_HEADERS = {"User-Agent": "CLEARFRONT-OSINT (+https://github.com/scottmartinanderson/CLEARFRONT)"}


def _email_hash(email: str) -> str:
    """Return the Gravatar identifier: md5 of the lowercased, trimmed email."""
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def _format_profile(entry: dict, email: str, gravatar_hash: str) -> str:
    """Render a public Gravatar profile entry into a structured summary."""
    lines = [f"Public Gravatar profile found for '{email}':", ""]

    def add(label: str, value) -> None:
        if value:
            lines.append(f"[+] {label}: {value}")

    add("Display name", entry.get("displayName") or entry.get("preferredUsername"))
    add("Name", (entry.get("name") or {}).get("formatted") if isinstance(entry.get("name"), dict) else None)
    add("Location", entry.get("currentLocation"))
    add("Pronouns", entry.get("pronouns"))
    job = entry.get("job_title") or entry.get("company")
    if entry.get("job_title") and entry.get("company"):
        job = f"{entry['job_title']} at {entry['company']}"
    add("Job", job)
    about = entry.get("aboutMe")
    if about:
        about = about.strip().replace("\n", " ")
        add("About", (about[:200] + "…") if len(about) > 200 else about)

    accounts = entry.get("accounts") or []
    verified = [a for a in accounts if isinstance(a, dict)]
    if verified:
        lines.append("")
        lines.append(f"Linked accounts ({len(verified)}):")
        for a in verified:
            svc = a.get("shortname") or a.get("name") or a.get("domain") or "account"
            url = a.get("url") or ""
            flag = " (verified)" if a.get("verified") in (True, "true") else ""
            lines.append(f"[+] {svc}{flag}: {url}".rstrip(": "))

    urls = [u for u in (entry.get("urls") or []) if isinstance(u, dict) and u.get("value")]
    if urls:
        lines.append("")
        lines.append(f"Listed URLs ({len(urls)}):")
        for u in urls:
            title = u.get("title") or "link"
            lines.append(f"[+] {title}: {u['value']}")

    lines += [
        "",
        f"Profile: {_PROFILE_LINK.format(hash=gravatar_hash)}",
        f"Avatar:  https://gravatar.com/avatar/{gravatar_hash}",
        "",
        "Source: Gravatar public profile (self-published by the account owner). "
        "Linked accounts are user-asserted; verify before relying on them.",
    ]
    return "\n".join(lines)


async def _fetch_json(session: aiohttp.ClientSession, url: str) -> dict | None:
    """GET a Gravatar profile JSON. Returns the parsed dict, or None on 404."""
    async with session.get(url, headers=_HEADERS) as resp:
        if resp.status == 404:
            return None
        if resp.status == 429:
            raise OSINTError("Gravatar rate limit exceeded. Try again shortly.")
        if resp.status != 200:
            raise ToolExecutionError(f"Gravatar returned HTTP {resp.status}.")
        return await resp.json(content_type=None)


async def _avatar_exists(session: aiohttp.ClientSession, url: str) -> bool:
    """Return True if a custom avatar exists for the hash (d=404 → 200 means yes)."""
    try:
        async with session.get(url, headers=_HEADERS) as resp:
            return resp.status == 200
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return False


async def run_gravatar_osint(
    email: str,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> str:
    """
    Look up an email's public Gravatar profile and avatar.

    Returns a structured summary of the public profile (display name, location,
    bio, linked/verified accounts, URLs) when one exists; otherwise reports
    whether the email at least has a registered Gravatar avatar. Returns a
    descriptive error string on failure rather than raising.

    Parameters
    ----------
    email:
        Target email address.
    timeout_seconds:
        HTTP request timeout in seconds.

    Returns
    -------
    str
        Formatted result string or a descriptive error message.
    """
    email = (email or "").strip()
    if not email or "@" not in email or email.startswith("-"):
        return "Error: a valid email address is required for a Gravatar lookup."

    gravatar_hash = _email_hash(email)
    logger.info("Starting Gravatar lookup for: %s", email)
    timeout_cfg = aiohttp.ClientTimeout(total=timeout_seconds)
    try:
        async with aiohttp.ClientSession(timeout=timeout_cfg) as session:
            data = await _fetch_json(session, _PROFILE_URL.format(hash=gravatar_hash))
            if data:
                entries = data.get("entry") or []
                if entries and isinstance(entries[0], dict):
                    return _format_profile(entries[0], email, gravatar_hash)
            # No public profile, does a custom avatar still exist?
            has_avatar = await _avatar_exists(session, _AVATAR_URL.format(hash=gravatar_hash))
        if has_avatar:
            return (
                f"No public Gravatar profile for '{email}', but the email has a registered "
                f"Gravatar avatar (so it is a real, Gravatar-linked address).\n"
                f"Avatar: https://gravatar.com/avatar/{gravatar_hash}"
            )
        return f"No Gravatar profile or avatar found for '{email}'."
    except OSINTError as exc:
        logger.warning("Gravatar lookup failed: %s", exc)
        return f"Scan error: {exc}"
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        logger.warning("Gravatar network error: %s", exc)
        return f"Scan error: network error querying Gravatar: {exc}"
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected error during Gravatar lookup.")
        return f"Internal error: {exc}"
