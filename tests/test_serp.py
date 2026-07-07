# tests/test_serp.py
"""Pluggable SERP backend: precedence, Serper.dev parsing, and graceful errors."""

from __future__ import annotations

import pytest

from clearfront import serp
from clearfront.tools.exceptions import OSINTError, ToolExecutionError


class _Resp:
    def __init__(self, status_code, payload=None, raise_json=False):
        self.status_code = status_code
        self._payload = payload
        self._raise_json = raise_json

    def json(self):
        if self._raise_json:
            raise ValueError("not json")
        return self._payload


def _clear_serp_env(monkeypatch):
    for k in ("SERPER_API_KEY", "BRIGHTDATA_API_KEY", "BRIGHTDATA_SERP_ZONE"):
        monkeypatch.delenv(k, raising=False)


def test_preferred_backend_precedence(monkeypatch):
    _clear_serp_env(monkeypatch)
    assert serp.preferred_backend() == "duckduckgo"
    monkeypatch.setenv("BRIGHTDATA_API_KEY", "x")
    monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "z")
    assert serp.preferred_backend() == "brightdata"
    monkeypatch.setenv("SERPER_API_KEY", "k")
    assert serp.preferred_backend() == "serper"  # Serper wins when all are set


def test_availability_helpers(monkeypatch):
    _clear_serp_env(monkeypatch)
    assert serp.serper_available() is False
    assert serp.brightdata_available() is False
    monkeypatch.setenv("SERPER_API_KEY", "k")
    assert serp.serper_available() is True
    monkeypatch.setenv("BRIGHTDATA_API_KEY", "x")
    assert serp.brightdata_available() is False  # needs the zone too
    monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "z")
    assert serp.brightdata_available() is True


def test_serper_search_parses_organic(monkeypatch):
    monkeypatch.setenv("SERPER_API_KEY", "k")
    payload = {
        "organic": [
            {"title": "T1", "link": "https://a.com", "snippet": "s1"},
            {"title": "T2", "link": "https://b.com", "snippet": "s2"},
        ]
    }
    monkeypatch.setattr(serp.requests, "post", lambda *a, **k: _Resp(200, payload))
    assert serp.serper_search("query", num=5) == [
        {"title": "T1", "url": "https://a.com", "snippet": "s1"},
        {"title": "T2", "url": "https://b.com", "snippet": "s2"},
    ]


def test_serper_search_no_key(monkeypatch):
    monkeypatch.delenv("SERPER_API_KEY", raising=False)
    with pytest.raises(OSINTError):
        serp.serper_search("q")


def test_serper_search_auth_error(monkeypatch):
    monkeypatch.setenv("SERPER_API_KEY", "k")
    monkeypatch.setattr(serp.requests, "post", lambda *a, **k: _Resp(401))
    with pytest.raises(OSINTError):
        serp.serper_search("q")


def test_serper_search_non_json(monkeypatch):
    monkeypatch.setenv("SERPER_API_KEY", "k")
    monkeypatch.setattr(serp.requests, "post", lambda *a, **k: _Resp(200, raise_json=True))
    with pytest.raises(ToolExecutionError):
        serp.serper_search("q")


async def test_dorks_live_reports_missing_backend(monkeypatch):
    _clear_serp_env(monkeypatch)
    from clearfront.tools.search_dorks_live import run_dorks_live_osint

    out = await run_dorks_live_osint("target")
    assert "no SERP backend configured" in out
    assert "SERPER_API_KEY" in out
