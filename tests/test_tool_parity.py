# tests/test_tool_parity.py
"""
Tool-surface parity + analyst-prompt calibration.

Guards against tool-surface drift (the terminal agent once shipped fewer tools
and a thinner report than the web console). Every surface, agent.py, mcp_server,
and the web console, must expose the same canonical 29 collection tools with no
duplicates, and the shared analyst prompt must carry the calibrated ICD-203
language.
"""

from __future__ import annotations

# The canonical set of collection tools every surface must expose.
EXPECTED_TOOLS = {
    "search_email",
    "search_username",
    "search_maigret",
    "search_breach",
    "search_gravatar",
    "search_emailrep",
    "search_crypto",
    "search_harvester",
    "search_whois",
    "search_ip",
    "search_exposure",
    "search_domain",
    "generate_dorks",
    "search_paste",
    "search_phone",
    "search_shodan",
    "search_virustotal",
    "search_censys",
    "search_ip2location",
    "search_abuseipdb",
    "search_github",
    "search_dns",
    "search_exif",
    "search_dorks_live",
    "scrape_url",
    "search_footprint",
    "search_crt",
    "search_wayback",
    "search_greynoise",
    "search_hudsonrock",
}


def test_expected_tool_count():
    assert len(EXPECTED_TOOLS) == 30


def test_no_duplicate_tool_definitions():
    from clearfront.agent import TOOL_DEFINITIONS

    names = [d["name"] for d in TOOL_DEFINITIONS]
    # A duplicate name is invalid for the Anthropic tools API and would be hidden
    # by the set-equality checks below.
    assert len(names) == len(set(names)), f"duplicate tool definition(s): {names}"


def test_no_duplicate_web_catalog():
    from clearfront.web_server import _TOOL_CATALOG

    names = [t["name"] for t in _TOOL_CATALOG]
    assert len(names) == len(set(names)), f"duplicate web catalog entr(ies): {names}"


def test_agent_definitions_cover_all_tools():
    from clearfront.agent import TOOL_DEFINITIONS

    names = {d["name"] for d in TOOL_DEFINITIONS}
    assert names == EXPECTED_TOOLS


def test_agent_map_matches_definitions():
    from clearfront.agent import _TOOL_MAP

    # The handler map is the tool set plus the internal deterministic-graph handler.
    assert set(_TOOL_MAP) == EXPECTED_TOOLS | {"investigate_graph"}


def test_agent_definitions_have_handlers():
    from clearfront.agent import _TOOL_MAP, TOOL_DEFINITIONS

    for d in TOOL_DEFINITIONS:
        assert d["name"] in _TOOL_MAP, f"{d['name']} defined but has no handler"


def test_mcp_handlers_match():
    from clearfront.mcp_server import _HANDLERS

    assert set(_HANDLERS) == EXPECTED_TOOLS


def test_web_catalog_matches():
    from clearfront.web_server import _TOOL_CATALOG

    names = {t["name"] for t in _TOOL_CATALOG}
    assert names == EXPECTED_TOOLS


def test_web_runners_cover_all_tools():
    from clearfront.web_server import _RUNNERS

    assert EXPECTED_TOOLS <= set(_RUNNERS)


def test_web_claude_tools_match_catalog():
    from clearfront.web_server import _CLAUDE_TOOLS

    names = {t["name"] for t in _CLAUDE_TOOLS}
    assert names == EXPECTED_TOOLS


def test_agent_prompt_is_calibrated():
    from clearfront.prompts import SYSTEM_PROMPT

    for phrase in (
        "almost certainly",  # calibrated likelihood term
        "analytic confidence",  # confidence stated separately
        "Assessment:",  # observed vs assessed split
        "reliability",  # per-finding source reliability
        "## INTELLIGENCE SUMMARY",  # structured report header
    ):
        assert phrase in SYSTEM_PROMPT, f"missing calibration cue: {phrase!r}"


def test_compact_prompt_is_calibrated():
    from clearfront.prompts import COMPACT_SYSTEM_PROMPT

    assert "almost certainly" in COMPACT_SYSTEM_PROMPT
    assert "## INTELLIGENCE SUMMARY" in COMPACT_SYSTEM_PROMPT
