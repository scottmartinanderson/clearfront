# clearfront/depth.py
"""Sweep depth: shared level metadata and the tool-round ceiling per level.

Faster, Balanced, and Deeper trade collection breadth (the number of tool
rounds the analyst runs) and the matching enrichment instruction, never the
analyst's reasoning or output quality. Deeper is the full default fan-out; its
ceiling stays env-tunable via ``OIS_MAX_TOOL_ROUNDS``. The lighter levels are
capped below it and never exceed it.

This module holds the pieces that are identical across surfaces: the level list
(used by the web console chip and the REPL ``depth`` command) and the per-level
round ceiling (used by both agent loops). The prompt wording itself is
surface-specific and lives with each surface: the web console keeps its own
graph-flavoured enrichment text in ``web_server``; the terminal agent's version
lives in ``prompts`` (see ``system_prompt_for_depth``).
"""

from __future__ import annotations

import os

DEFAULT = "deeper"

# User-facing labels and descriptions. The descriptions are kept identical to
# the web console's sweep-depth menu (clearfront/web/index.html depthLevels) so
# every surface describes the feature the same way.
LEVELS: list[dict[str, str]] = [
    {
        "v": "faster",
        "name": "Faster",
        "desc": "Checks fewer sources for a quick sweep. Finishes fast and uses less of your API budget.",
    },
    {
        "v": "balanced",
        "name": "Balanced",
        "desc": "Covers the main sources. A middle ground on time and cost.",
    },
    {
        "v": "deeper",
        "name": "Deeper",
        "desc": "Follows every lead for the most complete map, but takes longer and uses more of your API budget.",
    },
]

_VALUES = {level["v"] for level in LEVELS}


def normalize(depth: str | None) -> str:
    """Return a valid depth value, falling back to the default for anything unknown."""
    return depth if depth in _VALUES else DEFAULT


def rounds(depth: str) -> int:
    """Tool-round ceiling for a depth level. Deeper stays env-tunable (default 12);
    the lighter levels are capped below it and never exceed it."""
    ceiling = int(os.environ.get("OIS_MAX_TOOL_ROUNDS", "12"))
    return {"faster": min(4, ceiling), "balanced": min(8, ceiling)}.get(depth, ceiling)


def describe(depth: str) -> str:
    """One-line description for a depth value (for the REPL 'depth' command)."""
    for level in LEVELS:
        if level["v"] == depth:
            return level["desc"]
    return ""
