# tests/test_tool_cache.py
"""Per-run tool cache (ICE #16 safe core): unit behavior + web/agent wiring."""

from __future__ import annotations

from clearfront.tool_cache import ToolCache, is_cacheable, normalize_args


# ---------------------------------------------------------------------------
# normalize_args
# ---------------------------------------------------------------------------


def test_normalize_collapses_whitespace_but_keeps_case():
    assert normalize_args("  Example.com  ") == "Example.com"
    assert normalize_args("a\t b\n c") == "a b c"
    # Case is preserved: a false collision would return the wrong subject's data.
    assert normalize_args("User") != normalize_args("user")


def test_normalize_dict_is_order_independent():
    assert normalize_args({"a": "1", "b": "2"}) == normalize_args({"b": "2", "a": "1"})
    # String values inside dicts get the same whitespace treatment.
    assert normalize_args({"email": "  x@y.com "}) == normalize_args({"email": "x@y.com"})


def test_normalize_dict_and_string_differ():
    assert normalize_args("input") != normalize_args({"input": "input"})


# ---------------------------------------------------------------------------
# is_cacheable
# ---------------------------------------------------------------------------


def test_is_cacheable_accepts_real_results():
    assert is_cacheable("found 3 accounts") is True


def test_is_cacheable_rejects_empty_and_errors():
    assert is_cacheable("") is False
    assert is_cacheable("   ") is False
    assert is_cacheable("Error: timed out") is False
    assert is_cacheable("Tool call error: 'input' is required") is False
    assert is_cacheable("Internal error: boom") is False
    assert is_cacheable("Unknown tool: search_nope") is False
    assert is_cacheable(None) is False
    assert is_cacheable(123) is False


# ---------------------------------------------------------------------------
# ToolCache.run
# ---------------------------------------------------------------------------


async def test_run_memoizes_identical_call():
    cache = ToolCache()
    calls = []

    async def factory():
        calls.append(1)
        return "result-A"

    r1, cached1 = await cache.run("search_email", "a@b.com", factory)
    r2, cached2 = await cache.run("search_email", "a@b.com", factory)

    assert r1 == r2 == "result-A"
    assert cached1 is False and cached2 is True
    assert len(calls) == 1  # factory ran once, second call served from cache
    assert cache.misses == 1 and cache.hits == 1


async def test_run_distinct_args_run_separately():
    cache = ToolCache()
    calls = []

    async def factory_for(value):
        async def factory():
            calls.append(value)
            return f"result-{value}"

        return factory

    await cache.run("search_email", "a@b.com", await factory_for("a"))
    await cache.run("search_email", "c@d.com", await factory_for("c"))

    assert calls == ["a", "c"]
    assert cache.misses == 2 and cache.hits == 0


async def test_run_does_not_cache_errors():
    cache = ToolCache()
    calls = []

    async def factory():
        calls.append(1)
        return "Error: transient failure"

    await cache.run("search_ip", "1.2.3.4", factory)
    await cache.run("search_ip", "1.2.3.4", factory)

    # An operational error is never memoized, so an identical retry re-runs the tool.
    assert len(calls) == 2
    assert cache.hits == 0


async def test_whitespace_variants_share_a_slot():
    cache = ToolCache()
    calls = []

    async def factory():
        calls.append(1)
        return "ok"

    await cache.run("search_email", "a@b.com", factory)
    _, cached = await cache.run("search_email", "  a@b.com  ", factory)
    assert cached is True
    assert len(calls) == 1


# ---------------------------------------------------------------------------
# Web console wiring: _run_tool honors the per-run cache
# ---------------------------------------------------------------------------


async def test_web_run_tool_memoizes_with_cache(monkeypatch):
    from clearfront import web_server

    calls = []

    async def counting_runner(value, timeout):
        calls.append(value)
        return f"ran for {value}"

    monkeypatch.setitem(web_server._RUNNERS, "search_email", counting_runner)
    cache = ToolCache()

    r1 = await web_server._run_tool("search_email", "a@b.com", cache=cache)
    r2 = await web_server._run_tool("search_email", "a@b.com", cache=cache)

    assert r1 == r2 == "ran for a@b.com"
    assert len(calls) == 1


async def test_web_run_tool_without_cache_reruns(monkeypatch):
    from clearfront import web_server

    calls = []

    async def counting_runner(value, timeout):
        calls.append(value)
        return f"ran for {value}"

    monkeypatch.setitem(web_server._RUNNERS, "search_email", counting_runner)

    await web_server._run_tool("search_email", "a@b.com")
    await web_server._run_tool("search_email", "a@b.com")
    assert len(calls) == 2  # no cache -> every call hits the tool


async def test_web_separate_caches_do_not_share(monkeypatch):
    from clearfront import web_server

    calls = []

    async def counting_runner(value, timeout):
        calls.append(value)
        return f"ran for {value}"

    monkeypatch.setitem(web_server._RUNNERS, "search_email", counting_runner)

    # Two investigations = two caches. The second must not see the first's result,
    # or one subject's footprint would leak into another's report.
    await web_server._run_tool("search_email", "a@b.com", cache=ToolCache())
    await web_server._run_tool("search_email", "a@b.com", cache=ToolCache())
    assert len(calls) == 2


# ---------------------------------------------------------------------------
# Agent wiring: _execute_tool honors the per-run cache
# ---------------------------------------------------------------------------


async def test_agent_execute_tool_memoizes_with_cache(monkeypatch):
    from clearfront import agent

    calls = []

    async def counting_tool(args):
        calls.append(args)
        return "agent result"

    monkeypatch.setitem(agent._TOOL_MAP, "search_email", counting_tool)
    cache = ToolCache()

    r1 = await agent._execute_tool("search_email", {"email": "a@b.com"}, None, cache)
    r2 = await agent._execute_tool("search_email", {"email": "a@b.com"}, None, cache)

    assert r1 == r2 == "agent result"
    assert len(calls) == 1


async def test_agent_execute_tool_no_cache_reruns(monkeypatch):
    from clearfront import agent

    calls = []

    async def counting_tool(args):
        calls.append(args)
        return "agent result"

    monkeypatch.setitem(agent._TOOL_MAP, "search_email", counting_tool)

    await agent._execute_tool("search_email", {"email": "a@b.com"}, None)
    await agent._execute_tool("search_email", {"email": "a@b.com"}, None)
    assert len(calls) == 2


async def test_agent_run_context_has_fresh_cache_per_turn():
    # Each _AgentRunContext gets its own ToolCache, so a cache never outlives one turn.
    ctx_a = agent_run_context()
    ctx_b = agent_run_context()
    assert ctx_a.cache is not ctx_b.cache


def agent_run_context():
    from clearfront.agent import _AgentRunContext

    return _AgentRunContext(messages=[], tool_calls=[], on_tool_call=None)
