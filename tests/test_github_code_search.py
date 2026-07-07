# tests/test_github_code_search.py
"""GitHub code/secret search: report exposure locations + secret TYPE, never the value."""

from __future__ import annotations

from clearfront.tools import search_github as gh


def test_secret_types_detects_shapes():
    assert gh._secret_types_in(["key = AKIAIOSFODNN7EXAMPLE"]) == ["AWS access key"]
    assert "private key" in gh._secret_types_in(["-----BEGIN OPENSSH PRIVATE KEY-----"])
    assert "GitHub token" in gh._secret_types_in(["token: ghp_" + "a" * 36])


def test_secret_types_ignores_benign_code():
    assert gh._secret_types_in(["const total = sum(a, b)", "# just a comment"]) == []


async def test_code_exposure_reports_location_and_type_not_value(monkeypatch):
    async def fake_search_code(session, query):
        return [
            {
                "repo": "acme/app",
                "path": "config/prod.env",
                "url": "https://github.com/acme/app/blob/main/config/prod.env",
                "secrets": ["AWS access key"],
            }
        ]

    monkeypatch.setattr(gh, "_search_code", fake_search_code)
    out = await gh._gather_code_exposure(None, ["johndoe"])

    assert "acme/app/config/prod.env" in out
    assert "AWS access key" in out
    assert "Possible secret exposure" in out
    # The raw secret value must never leak into the report.
    assert "AKIA" not in out


async def test_code_exposure_dedupes_across_queries(monkeypatch):
    async def fake_search_code(session, query):
        return [{"repo": "a/b", "path": "x.py", "url": "u", "secrets": []}]

    monkeypatch.setattr(gh, "_search_code", fake_search_code)
    out = await gh._gather_code_exposure(None, ["q1", "q2", "q3"])
    assert out.count("a/b/x.py") == 1


async def test_code_exposure_empty_when_no_hits(monkeypatch):
    async def fake_search_code(session, query):
        return []

    monkeypatch.setattr(gh, "_search_code", fake_search_code)
    assert await gh._gather_code_exposure(None, ["johndoe"]) == ""
