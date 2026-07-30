# tests/test_entrypoints.py
"""
Import every shipped entry point.

This exists because of a real outage. `mcp` 2.0.0 shipped on 2026-07-28 and
changed the `Server` API, while pyproject declared an unbounded `mcp>=1.28.1`.
Every fresh `pip install clearfront` from that date resolved to the new major
and `clearfront.mcp_server` died at import. The CLI was unaffected, so a
cold-install check that only ran `clearfront --version` passed while the MCP
server was broken in the wild for two days.

Nothing in the repo was wrong. The break came from a dependency resolving
forward, which only surfaces when something actually imports the module against
current dependencies. CI installs fresh on every run, so these imports are the
tripwire. They are deliberately dumb: no mocking, no fixtures, just import the
module the console scripts and the MCP client would import.

Keep one test per shipped surface. If a new entry point is added to
[project.scripts] or the MCP manifest, add it here too.
"""

from __future__ import annotations

import importlib

import pytest

# module path -> the callable the entry point advertises, or None for a plain import
ENTRY_POINTS = {
    "clearfront.cli": "main",
    "clearfront.mcp_server": "main",
    "clearfront.web_server": "run_server",
}


@pytest.mark.parametrize("module_path,attr", sorted(ENTRY_POINTS.items()))
def test_entry_point_imports(module_path: str, attr: str) -> None:
    """The module must import cleanly against the installed dependency set."""
    module = importlib.import_module(module_path)
    assert hasattr(module, attr), f"{module_path} is missing its entry point {attr}()"
    assert callable(getattr(module, attr))


def test_version_is_resolvable() -> None:
    """`clearfront --version` reads this, so a broken metadata lookup breaks the flag."""
    from clearfront import __version__

    assert __version__
    assert __version__ != "unknown", "package metadata is not installed; __version__ fell back"


def test_console_scripts_are_declared() -> None:
    """The console scripts in pyproject must still resolve to importable targets."""
    from importlib.metadata import entry_points

    scripts = {ep.name: ep.value for ep in entry_points(group="console_scripts")}
    for name in ("clearfront", "clearfront-mcp"):
        assert name in scripts, f"console script {name} is not installed"
        module_path, _, attr = scripts[name].partition(":")
        module = importlib.import_module(module_path)
        assert hasattr(module, attr), f"{scripts[name]} does not resolve"
