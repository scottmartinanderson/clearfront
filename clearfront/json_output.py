# clearfront/json_output.py
"""
JSON export utility for Clearfront tool results.

Provides a consistent schema for structured output across the CLI and MCP server.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone


def format_tool_result(
    tool: str,
    target: str,
    result: str,
    error: str | None = None,
) -> dict:
    """
    Build a structured dict representing one tool's output.

    Schema
    ------
    {
        "tool":      str,        # tool name
        "target":    str,        # target passed to the tool
        "timestamp": str,        # ISO-8601 UTC timestamp
        "results":   list[str],  # non-empty output lines
        "error":     str | null  # error message if the call failed
    }
    """
    lines = [ln for ln in result.splitlines() if ln.strip()] if result else []
    return {
        "tool": tool,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": lines,
        "error": error,
    }


def to_json(
    tool: str,
    target: str,
    result: str,
    error: str | None = None,
) -> str:
    """Return a pretty-printed JSON string of the tool result."""
    return json.dumps(format_tool_result(tool, target, result, error), indent=2)
