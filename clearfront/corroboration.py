"""Per-run cross-tool corroboration notes (ICE #16, the additive/safe half).

Several tools surface the same account. When you investigate an email, holehe,
sherlock, maigret, and footprint all hunt for profiles, so the model routinely sees
the same ``github.com/alex`` reported three or four times with no unified signal.

This annotates a tool result with a short note when a profile URL it reports was
ALSO reported by a *different* tool earlier in the same run, giving the analyst the
"N independent tools agree" corroboration signal.

It is deliberately additive and never merges, dedupes, reorders, or removes anything
the model sees; it only appends a clearly marked ``[corroboration]`` line. So a missed
or mistaken extraction can at worst produce a smaller or absent note, never a corrupted
or hidden result. That safety property is why this is the shipped half of ICE #16 and
the full rewrite-what-the-model-sees entity normalization stays deferred.

Corroboration is inherently retrospective: the first tool to report a profile has
nothing to confirm yet, so the note appears on the second (and later) tools' results.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Find http(s) URLs embedded in free text (stop at whitespace or common delimiters).
_URL_FIND_RE = re.compile(r'https?://[^\s<>"\')\]}]+', re.IGNORECASE)

# A plausible profile handle: the first path segment of a profile URL.
_HANDLE_RE = re.compile(r"^[A-Za-z0-9._-]{2,40}$")

# First path segments that are site chrome, not a person's handle.
_NON_PROFILE_SEGMENTS = frozenset(
    {
        "login", "signin", "sign-in", "signup", "sign-up", "register", "account",
        "accounts", "about", "home", "index", "index.html", "help", "support",
        "search", "explore", "intent", "share", "tos", "terms", "privacy", "policy",
        "settings", "user", "users", "profile", "profiles", "pages", "page", "auth",
        "oauth", "api", "hashtag", "tag", "tags", "category", "feed", "rss", "contact",
        "download", "downloads", "docs", "blog", "news", "status", "en", "www",
    }
)

# Search/aggregator hosts whose URLs are queries or generic, never a unique profile.
_GENERIC_HOSTS = frozenset(
    {
        "google.com", "bing.com", "duckduckgo.com", "yahoo.com", "baidu.com",
        "yandex.com", "archive.org", "web.archive.org", "t.co", "bit.ly",
    }
)

_MAX_ITEMS = 8


def _profile_keys(text: str) -> set[str]:
    """Return normalized ``host/handle`` keys for profile-looking URLs in *text*.

    Conservative on purpose: a URL only qualifies if it has a host and a plausible
    first-path-segment handle, and site chrome / search hosts are excluded. Two
    different people are therefore very unlikely to collide on one key, which keeps
    a false "corroborated" note from ever appearing.
    """
    keys: set[str] = set()
    for raw in _URL_FIND_RE.findall(text):
        raw = raw.rstrip(".,;:!?)]}'\"")
        try:
            parsed = urlparse(raw)
        except ValueError:
            continue
        host = parsed.netloc.lower().split("@")[-1].split(":")[0]
        if host.startswith("www."):
            host = host[4:]
        if not host or host in _GENERIC_HOSTS:
            continue
        segments = [s for s in parsed.path.split("/") if s]
        if not segments:
            continue
        handle = segments[0]
        if handle.lower() in _NON_PROFILE_SEGMENTS or not _HANDLE_RE.match(handle):
            continue
        keys.add(f"{host}/{handle.lower()}")
    return keys


class CorroborationLedger:
    """Tracks which tools reported each profile across ONE investigation run.

    Create one per run (never a module global); like the tool cache it is scoped to a
    single investigation so cross-tool signals never leak across targets or runs.
    """

    def __init__(self) -> None:
        self._by_key: dict[str, set[str]] = {}

    def note(self, tool_name: str, result: str) -> str:
        """Record this tool's profiles and return an additive corroboration note.

        The returned note names profiles in *result* that a DIFFERENT tool already
        reported earlier this run. Returns ``""`` when there is nothing to corroborate.
        Never modifies *result*; the caller appends the note only if it is non-empty.
        """
        if not isinstance(result, str) or not result:
            return ""
        corroborated: list[tuple[str, list[str]]] = []
        for key in sorted(_profile_keys(result)):
            others = self._by_key.get(key, set()) - {tool_name}
            if others:
                corroborated.append((key, sorted(others)))
            self._by_key.setdefault(key, set()).add(tool_name)
        if not corroborated:
            return ""
        shown = corroborated[:_MAX_ITEMS]
        parts = [f"{key} (also reported by {', '.join(tools)})" for key, tools in shown]
        extra = len(corroborated) - len(shown)
        if extra > 0:
            parts.append(f"and {extra} more")
        return (
            "\n[corroboration] Profiles here independently reported by other tools this "
            "run, treat as higher-confidence: " + "; ".join(parts) + "."
        )
