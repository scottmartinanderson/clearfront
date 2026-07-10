"""Sweep-effort invariants shared by the web console and the terminal agent."""

from clearfront import effort
from clearfront.prompts import (
    SYSTEM_PROMPT,
    AGENT_ENRICH,
    AGENT_MODE_LINE,
    _ENRICH_DEEPER,
    system_prompt_for_effort,
)


def test_rounds_ceiling_per_level():
    assert effort.rounds("faster") == 4
    assert effort.rounds("balanced") == 8
    assert effort.rounds("deeper") == 12
    # Unknown level falls back to the deeper ceiling.
    assert effort.rounds("bogus") == 12


def test_rounds_respects_env_ceiling(monkeypatch):
    monkeypatch.setenv("OIS_MAX_TOOL_ROUNDS", "6")
    # Lighter levels are capped below the ceiling and never exceed it.
    assert effort.rounds("faster") == 4
    assert effort.rounds("balanced") == 6  # min(8, 6)
    assert effort.rounds("deeper") == 6


def test_normalize():
    assert effort.normalize("faster") == "faster"
    assert effort.normalize("balanced") == "balanced"
    assert effort.normalize("deeper") == "deeper"
    assert effort.normalize("bogus") == "deeper"
    assert effort.normalize(None) == "deeper"


def test_levels_match_console_descriptions():
    # The descriptions must stay identical to the web console's depthLevels
    # (clearfront/web/index.html) so both surfaces read the same.
    by_v = {level["v"]: level for level in effort.LEVELS}
    assert by_v["faster"]["desc"] == (
        "Checks fewer sources for a quick sweep. Finishes fast and uses less of your API budget."
    )
    assert by_v["balanced"]["desc"] == (
        "Covers the main sources. A middle ground on time and cost."
    )
    assert by_v["deeper"]["desc"] == (
        "Follows every lead for the most complete map, but takes longer and uses more of your API budget."
    )


def test_deeper_prompt_is_byte_identical():
    # Deeper must not change the historical prompt at all.
    assert system_prompt_for_effort("deeper") == SYSTEM_PROMPT
    assert system_prompt_for_effort("bogus") == SYSTEM_PROMPT


def test_deeper_enrich_sentence_present_verbatim():
    # The swap depends on this exact sentence living in SYSTEM_PROMPT.
    assert _ENRICH_DEEPER in SYSTEM_PROMPT


def test_lighter_levels_swap_enrich_and_prepend_mode_line():
    for level in ("faster", "balanced"):
        shaped = system_prompt_for_effort(level)
        assert shaped.startswith(AGENT_MODE_LINE[level])
        assert AGENT_ENRICH[level] in shaped
        # The aggressive deeper instruction must be gone, not merely appended to.
        assert _ENRICH_DEEPER not in shaped


def test_web_and_agent_share_the_round_ceiling():
    from clearfront import web_server

    # The web console keeps the internal name _depth_rounds; it aliases the
    # shared effort.rounds so both surfaces use one ceiling.
    assert web_server._depth_rounds is effort.rounds
