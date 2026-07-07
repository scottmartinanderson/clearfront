# tests/test_wayback_greynoise.py
"""Wayback (CDX) and GreyNoise Community tools: validation + deliberate non-pivot design."""

from __future__ import annotations

from clearfront.tools.search_greynoise import _is_ip, run_greynoise_osint
from clearfront.tools.search_wayback import _clean_host, run_wayback_osint


def test_wayback_clean_host():
    assert _clean_host("https://Example.com/some/path") == "example.com"
    assert _clean_host("*.example.com") == "example.com"
    assert _clean_host("  example.com.  ") == "example.com"


async def test_wayback_rejects_invalid_domain():
    out = await run_wayback_osint("not a domain")
    assert out.startswith("Error:")


def test_greynoise_ip_validation():
    assert _is_ip("8.8.8.8") is True
    assert _is_ip("2001:4860:4860::8888") is True
    assert _is_ip("not-an-ip") is False
    assert _is_ip("999.999.999.999") is False


async def test_greynoise_rejects_invalid_ip():
    out = await run_greynoise_osint("not-an-ip")
    assert out.startswith("Error:")


def test_wayback_and_greynoise_are_not_auto_pivoted():
    # Both are analyst-invoked enrichments (Wayback is a nonprofit archive; GreyNoise
    # Community is capped at 50/week), so they must NOT be in the auto-pivot routes.
    from clearfront import pivot

    routed: set[str] = set()
    for tools in pivot._TOOL_ROUTES.values():
        routed.update(tools)
    assert "search_wayback" not in routed
    assert "search_greynoise" not in routed
