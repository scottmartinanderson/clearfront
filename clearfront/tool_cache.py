"""Per-run tool-result cache (ICE #16, session-cache core).

An agentic investigation runs a tool loop of a dozen or more rounds, and the model
routinely re-requests the same tool with the same target across those rounds (for
example after a pivot re-surfaces an email it already looked up). This memoizes
``(tool, normalized-args) -> result`` for the lifetime of ONE investigation so those
repeats are served from memory instead of re-hitting the network.

Scope is deliberately per-run. Each :class:`ToolCache` instance belongs to a single
investigation and is discarded when it ends, so a cached result can never leak across
targets, across separate web requests, or across REPL turns. There is no module-level
cache and there must never be one: a long-lived cache would serve stale data and blur
one subject's footprint into another's.

This is the safe half of ICE #16. The cross-tool entity-normalization half (rewriting
arguments so that, say, a bare handle and a profile URL collapse to one key) is
intentionally deferred: it changes what the model sees and can degrade report quality.
Here we only skip provably redundant work, never alter a tool's inputs or outputs.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

# Result prefixes that mark an operational or transient failure (a timeout, an
# unreachable service, a validation bounce). These are never memoized so the model can
# retry the identical call later in the same run and get a fresh attempt.
_ERROR_SENTINELS = (
    "Error:",
    "Tool call error:",
    "Internal error:",
    "Unknown tool:",
)


def normalize_args(args: Any) -> str:
    """Return a stable key fragment for a tool's arguments.

    Case is preserved and normalization stays minimal on purpose. A false cache hit
    (two genuinely different inputs colliding on one key) would return the wrong
    subject's data, whereas a missed hit only costs one redundant lookup, so the key is
    kept conservative. Strings are stripped and their internal whitespace collapsed;
    dicts are serialized as sorted JSON with the same treatment applied to each string
    value, so argument order never changes the key.
    """
    if isinstance(args, str):
        return " ".join(args.split())
    if isinstance(args, dict):
        norm = {
            key: (" ".join(value.split()) if isinstance(value, str) else value)
            for key, value in args.items()
        }
        return json.dumps(norm, sort_keys=True, default=str)
    return str(args)


def is_cacheable(result: Any) -> bool:
    """True if ``result`` should be memoized: a non-empty string that is not an error."""
    if not isinstance(result, str):
        return False
    stripped = result.strip()
    if not stripped:
        return False
    return not stripped.startswith(_ERROR_SENTINELS)


class ToolCache:
    """In-memory memo of tool results for a single investigation run.

    Not thread-safe, and it does not need to be: within one agentic run tools are
    awaited one at a time, so there is never concurrent access to a given instance.
    Construct one per run; never share it across runs or promote it to a global.
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self.hits = 0
        self.misses = 0

    def key(self, tool_name: str, args: Any) -> str:
        # NUL separates name from args so no tool name / argument pair can be ambiguous.
        return f"{tool_name}\x00{normalize_args(args)}"

    def peek(self, tool_name: str, args: Any) -> str | None:
        """Return the memoized result for this call, or ``None``. Does not count a hit."""
        return self._store.get(self.key(tool_name, args))

    def put(self, tool_name: str, args: Any, result: str) -> None:
        """Memoize a successful result. Errors and empty results are ignored."""
        if is_cacheable(result):
            self._store[self.key(tool_name, args)] = result

    async def run(
        self,
        tool_name: str,
        args: Any,
        factory: Callable[[], Awaitable[str]],
    ) -> tuple[str, bool]:
        """Return ``(result, was_cached)``.

        On a hit, return the memoized result without calling ``factory``. On a miss,
        await ``factory`` (the real tool invocation), memoize a cacheable result, and
        return it. ``factory`` exceptions propagate and nothing is memoized, so a call
        that raised can be retried.
        """
        cached = self.peek(tool_name, args)
        if cached is not None:
            self.hits += 1
            return cached, True
        self.misses += 1
        result = await factory()
        self.put(tool_name, args, result)
        return result, False
