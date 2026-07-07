# clearfront/tools/search_github.py
"""
GitHub OSINT integration.

Searches GitHub for a username, email, or keyword. For direct username
matches, returns profile data, public repos, and emails discovered from
commit history. For other queries, returns the top user search hits.
Optional GITHUB_TOKEN env var raises the API rate limit from 60 to 5000
requests per hour.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re

import aiohttp

logger = logging.getLogger(__name__)

_API_BASE = "https://api.github.com"
_DEFAULT_TIMEOUT = 30
_MAX_REPOS = 10
_COMMIT_REPOS_SAMPLE = 3
_COMMITS_PER_REPO = 5
_MAX_CODE_QUERIES = 3
_CODE_RESULTS_PER_QUERY = 5

# High-signal secret shapes. Used only to FLAG and (by name) label an exposure.
# We report the location plus the secret TYPE; the matched secret value is never
# returned and the raw file is never fetched, keeping this passive and authorized.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("GitHub PAT", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("OpenAI/Anthropic key", re.compile(r"sk-(?:ant-)?[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
]


def _secret_types_in(fragments: list[str]) -> list[str]:
    """Return the NAMES of secret shapes present in code-match fragments.

    Only pattern names are returned, never the matched secret text.
    """
    found: list[str] = []
    for frag in fragments:
        for name, pat in _SECRET_PATTERNS:
            if pat.search(frag) and name not in found:
                found.append(name)
    return found


async def _search_code(session: aiohttp.ClientSession, query: str) -> list[dict]:
    """Search public code for *query* via the authenticated code-search API.

    Returns a list of {repo, path, url, secrets} dicts. Reports exposure only:
    it never fetches the raw file and never surfaces a secret value. Degrades to
    an empty list on rate-limit (403), a rejected query (422), or any error.
    """
    headers = {"Accept": "application/vnd.github.text-match+json"}
    params = {"q": query, "per_page": _CODE_RESULTS_PER_QUERY}
    try:
        async with session.get(
            f"{_API_BASE}/search/code", params=params, headers=headers
        ) as resp:
            if resp.status in (403, 422):
                return []
            resp.raise_for_status()
            data = await resp.json()
    except Exception:
        return []

    items = data.get("items", []) if isinstance(data, dict) else []
    findings: list[dict] = []
    for it in items:
        frags = [
            m.get("fragment", "")
            for m in (it.get("text_matches") or [])
            if isinstance(m, dict)
        ]
        findings.append(
            {
                "repo": (it.get("repository") or {}).get("full_name", ""),
                "path": it.get("path", ""),
                "url": it.get("html_url", ""),
                "secrets": _secret_types_in(frags),
            }
        )
    return findings


async def _gather_code_exposure(session: aiohttp.ClientSession, queries: list[str]) -> str:
    """Run up to _MAX_CODE_QUERIES code searches and format deduped exposure."""
    seen: set[tuple[str, str]] = set()
    hits: list[dict] = []
    for q in queries[:_MAX_CODE_QUERIES]:
        if not q.strip():
            continue
        for f in await _search_code(session, q):
            key = (f["repo"], f["path"])
            if key in seen:
                continue
            seen.add(key)
            hits.append(f)
    if not hits:
        return ""
    lines = [f"[GitHub] Code search: {len(hits)} public code reference(s) to the target."]
    for f in hits:
        lines.append(f"  • {f['repo']}/{f['path']} , {f['url']}")
        if f["secrets"]:
            lines.append(
                f"    Possible secret exposure ({', '.join(f['secrets'])}); "
                "value redacted, verify and rotate."
            )
    return "\n".join(lines)


def _build_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _get(
    session: aiohttp.ClientSession,
    url: str,
    params: dict | None = None,
) -> dict | list | None:
    async with session.get(url, params=params) as resp:
        if resp.status == 404:
            return None
        resp.raise_for_status()
        return await resp.json()


async def _fetch_user(session: aiohttp.ClientSession, login: str) -> dict | None:
    result = await _get(session, f"{_API_BASE}/users/{login}")
    return result if isinstance(result, dict) else None


async def _fetch_repos(session: aiohttp.ClientSession, login: str) -> list[dict]:
    result = await _get(
        session,
        f"{_API_BASE}/users/{login}/repos",
        params={"per_page": _MAX_REPOS, "sort": "updated"},
    )
    return result if isinstance(result, list) else []


async def _discover_emails(
    session: aiohttp.ClientSession,
    login: str,
    repos: list[dict],
) -> set[str]:
    emails: set[str] = set()
    for repo in repos[:_COMMIT_REPOS_SAMPLE]:
        try:
            commits = await _get(
                session,
                f"{_API_BASE}/repos/{login}/{repo['name']}/commits",
                params={"author": login, "per_page": _COMMITS_PER_REPO},
            )
            if not isinstance(commits, list):
                continue
            for commit in commits:
                author = commit.get("commit", {}).get("author", {})
                email = author.get("email", "")
                if email and not email.endswith("noreply.github.com"):
                    emails.add(email)
        except Exception:
            pass
    return emails


async def _search_users(session: aiohttp.ClientSession, query: str) -> list[dict]:
    data = await _get(
        session,
        f"{_API_BASE}/search/users",
        params={"q": query, "per_page": 5},
    )
    if not isinstance(data, dict):
        return []
    return data.get("items", [])


def _format_profile(user: dict, repos: list[dict], emails: set[str]) -> str:
    lines = [
        f"[GitHub] Login: {user.get('login', '')}",
        f"[GitHub] Name: {user.get('name') or 'N/A'}",
        f"[GitHub] Bio: {user.get('bio') or 'N/A'}",
        f"[GitHub] Location: {user.get('location') or 'N/A'}",
        f"[GitHub] Company: {user.get('company') or 'N/A'}",
        f"[GitHub] Email (profile): {user.get('email') or 'N/A'}",
        f"[GitHub] Followers: {user.get('followers', 0)}  |  Following: {user.get('following', 0)}",
        f"[GitHub] Public repos: {user.get('public_repos', 0)}  |  Gists: {user.get('public_gists', 0)}",
        f"[GitHub] Account type: {user.get('type', 'N/A')}",
        f"[GitHub] Created: {user.get('created_at', 'N/A')}",
        f"[GitHub] Profile URL: {user.get('html_url', '')}",
    ]
    if emails:
        lines.append(f"[GitHub] Emails found in commits: {', '.join(sorted(emails))}")
    if repos:
        lines.append(f"\n[GitHub] Recent repositories (up to {_MAX_REPOS}):")
        for repo in repos:
            stars = repo.get("stargazers_count", 0)
            lang = repo.get("language") or "unknown"
            desc = (repo.get("description") or "").strip()
            suffix = f", {desc[:80]}" if desc else ""
            lines.append(f"  • {repo['name']} [{lang}] ★{stars}{suffix}")
    return "\n".join(lines)


async def run_github_osint(query: str, timeout_seconds: int = _DEFAULT_TIMEOUT, *, api_key: str | None = None) -> str:
    """Search GitHub for a username, email, or keyword. GITHUB_TOKEN increases rate limits."""
    query = query.strip()
    if not query:
        return "Error: query cannot be empty."

    token = api_key or os.environ.get("GITHUB_TOKEN") or None
    timeout_cfg = aiohttp.ClientTimeout(total=timeout_seconds)

    try:
        async with aiohttp.ClientSession(
            headers=_build_headers(token),
            timeout=timeout_cfg,
        ) as session:
            user = await _fetch_user(session, query)
            if user:
                repos = await _fetch_repos(session, query)
                emails = await _discover_emails(session, query, repos)
                base_text = _format_profile(user, repos, emails)
                code_queries = [query, *[f'"{e}"' for e in sorted(emails)]]
            else:
                users = await _search_users(session, query)
                if not users:
                    base_text = f"[GitHub] No users found for query: '{query}'."
                    code_queries = [f'"{query}"' if " " in query else query]
                else:
                    lines = [f"[GitHub] Search results for '{query}' ({len(users)} match(es)):"]
                    for u in users:
                        lines.append(
                            f"  • {u.get('login')}, {u.get('html_url')} (type: {u.get('type', '?')})"
                        )
                    base_text = "\n".join(lines)
                    code_queries = [f'"{query}"' if " " in query else query]

            # Code/secret search is authenticated-only on GitHub, so it runs only
            # with a token. It reports exposure locations (repo/path) and the TYPE
            # of any secret shape found, never the secret value or raw file.
            if token:
                code_text = await _gather_code_exposure(session, code_queries)
                if code_text:
                    base_text += "\n\n" + code_text
            elif user:
                base_text += "\n\n[GitHub] Code/secret search skipped (set GITHUB_TOKEN to enable)."
            return base_text

    except asyncio.TimeoutError:
        return f"Scan error: GitHub request timed out after {timeout_seconds}s."
    except aiohttp.ClientResponseError as exc:
        if exc.status == 403:
            return "Scan error: GitHub rate limit exceeded. Set GITHUB_TOKEN for higher limits."
        if exc.status == 401:
            return "Scan error: Invalid GITHUB_TOKEN."
        return f"Scan error: GitHub API error HTTP {exc.status}."
    except aiohttp.ClientError as exc:
        return f"Scan error: Network error querying GitHub: {exc}"
    except Exception as exc:
        logger.exception("Unexpected error during GitHub lookup.")
        return f"Internal error: {exc}"
