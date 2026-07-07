# tests/test_corroboration.py
"""Cross-tool corroboration notes (ICE #16 additive half): additive, never destructive."""

from __future__ import annotations

from clearfront.corroboration import CorroborationLedger, _profile_keys


# ---------------------------------------------------------------------------
# _profile_keys extraction
# ---------------------------------------------------------------------------


def test_extracts_host_and_handle():
    keys = _profile_keys("Found https://github.com/alex and http://www.twitter.com/alex/")
    assert keys == {"github.com/alex", "twitter.com/alex"}


def test_strips_trailing_punctuation_and_www():
    assert _profile_keys("see https://github.com/alex.") == {"github.com/alex"}
    assert _profile_keys("(https://www.reddit.com/alice)") == {"reddit.com/alice"}


def test_prefixed_profiles_are_conservatively_skipped():
    # reddit.com/u/bob keys on the first segment "u" (too short) rather than guessing
    # "bob" -- deliberately conservative: skipping is safe, a wrong key is not (a user
    # "u/bob" must never corroborate a subreddit "r/bob").
    assert _profile_keys("https://reddit.com/u/bob") == set()


def test_excludes_site_chrome_segments():
    # login/search/etc. are site chrome, not a person's handle.
    assert _profile_keys("https://twitter.com/login") == set()
    assert _profile_keys("https://github.com/search?q=x") == set()
    assert _profile_keys("https://example.com/about") == set()


def test_excludes_generic_search_hosts():
    assert _profile_keys("https://google.com/alex https://bing.com/alex") == set()


def test_bare_domain_is_not_a_profile():
    # Site-level presence (no handle) does not create a corroboration key.
    assert _profile_keys("https://github.com") == set()
    assert _profile_keys("https://github.com/") == set()


def test_ignores_non_urls():
    assert _profile_keys("no urls here, just github and twitter") == set()


# ---------------------------------------------------------------------------
# CorroborationLedger.note
# ---------------------------------------------------------------------------


def test_first_sighting_has_no_note():
    led = CorroborationLedger()
    assert led.note("search_username", "https://github.com/alex") == ""


def test_second_tool_triggers_corroboration():
    led = CorroborationLedger()
    led.note("search_username", "https://github.com/alex")
    note = led.note("search_email", "https://github.com/alex")
    assert note.startswith("\n[corroboration]")
    assert "github.com/alex" in note
    assert "search_username" in note  # names the tool that corroborated it


def test_same_tool_does_not_corroborate_itself():
    led = CorroborationLedger()
    led.note("search_username", "https://github.com/alex")
    # Same tool, same profile again (e.g. a cached re-call) -> no false corroboration.
    assert led.note("search_username", "https://github.com/alex") == ""


def test_different_handles_same_host_never_collide():
    # The core safety property: two different people on the same platform must NOT
    # read as corroborating each other.
    led = CorroborationLedger()
    led.note("search_username", "https://twitter.com/alice")
    assert led.note("search_email", "https://twitter.com/bob") == ""


def test_note_is_additive_only():
    # note() returns a string to append; it never mutates or returns the raw result.
    led = CorroborationLedger()
    led.note("search_username", "https://github.com/alex")
    note = led.note("search_maigret", "raw maigret output https://github.com/alex here")
    assert note != ""
    assert note.lstrip().startswith("[corroboration]")
    # The raw result text is not part of what note() returns.
    assert "raw maigret output" not in note


def test_caps_number_of_items():
    led = CorroborationLedger()
    seed = " ".join(f"https://github.com/user{i}" for i in range(15))
    led.note("search_username", seed)
    note = led.note("search_maigret", seed)
    assert "and 7 more" in note  # 15 corroborated, 8 shown


def test_handles_garbage_and_empty_input():
    led = CorroborationLedger()
    assert led.note("t", "") == ""
    assert led.note("t", None) == ""  # type: ignore[arg-type]
    assert led.note("t", "https://") == ""  # no host/handle, no crash


# ---------------------------------------------------------------------------
# Integration: web _run_tool appends the note but preserves the raw output
# ---------------------------------------------------------------------------


async def test_web_run_tool_appends_note_and_preserves_raw(monkeypatch):
    from clearfront import web_server

    async def runner_username(value, timeout):
        return "sherlock: https://github.com/alex"

    async def runner_email(value, timeout):
        return "holehe result body https://github.com/alex found"

    monkeypatch.setitem(web_server._RUNNERS, "search_username", runner_username)
    monkeypatch.setitem(web_server._RUNNERS, "search_email", runner_email)
    led = CorroborationLedger()

    r1 = await web_server._run_tool("search_username", "alex", ledger=led)
    r2 = await web_server._run_tool("search_email", "alex@x.com", ledger=led)

    assert "[corroboration]" not in r1  # first sighting, no note
    # Second tool: raw output fully intact AND the note appended.
    assert "holehe result body https://github.com/alex found" in r2
    assert "[corroboration]" in r2 and "search_username" in r2


async def test_web_run_tool_without_ledger_is_unchanged(monkeypatch):
    from clearfront import web_server

    async def runner(value, timeout):
        return "https://github.com/alex"

    monkeypatch.setitem(web_server._RUNNERS, "search_username", runner)
    out = await web_server._run_tool("search_username", "alex")
    assert out == "https://github.com/alex"  # no ledger -> byte-for-byte unchanged


# ---------------------------------------------------------------------------
# Integration: agent _execute_tool
# ---------------------------------------------------------------------------


async def test_agent_execute_tool_corroborates(monkeypatch):
    from clearfront import agent

    async def tool_a(args):
        return "https://github.com/alex"

    async def tool_b(args):
        return "https://github.com/alex"

    monkeypatch.setitem(agent._TOOL_MAP, "search_username", tool_a)
    monkeypatch.setitem(agent._TOOL_MAP, "search_maigret", tool_b)
    led = CorroborationLedger()

    await agent._execute_tool("search_username", {"input": "alex"}, None, None, led)
    r2 = await agent._execute_tool("search_maigret", {"input": "alex"}, None, None, led)
    assert "[corroboration]" in r2 and "search_username" in r2


def test_agent_context_has_fresh_ledger_per_turn():
    from clearfront.agent import _AgentRunContext

    a = _AgentRunContext(messages=[], tool_calls=[], on_tool_call=None)
    b = _AgentRunContext(messages=[], tool_calls=[], on_tool_call=None)
    assert a.ledger is not b.ledger
