# tests/test_brightdata.py
"""
Unit tests for the Bright Data integration tools:
  - search_dorks_live (clearfront/tools/search_dorks_live.py)
  - scrape_url        (clearfront/tools/scrape_url.py)

All HTTP calls are mocked, no real network requests are made.

Mock shapes match the verified API behaviour:
  SERP (format=raw, data_format=parsed_light): response.json() → {"organic": [...]}
  Web Unlocker (format=raw, data_format=markdown): response.text → "<markdown string>"
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_serp_response(status_code: int, json_body: dict | None = None) -> MagicMock:
    """Mock for SERP calls: response.json() returns parsed SERP data."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    # The empty-body guard reads response.text before parsing.
    resp.text = json.dumps(json_body) if json_body else "{}"
    return resp


def _mock_unlocker_response(status_code: int, text: str = "") -> MagicMock:
    """Mock for Web Unlocker calls: response.text returns the markdown body directly."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def _mock_status_response(status_code: int, json_body: dict | None = None) -> MagicMock:
    """Mock for GET /status, the account-state probe."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    return resp


@pytest.fixture(autouse=True)
def _reset_status_cache():
    """The account-state probe caches per key for a minute. Isolate every test from it."""
    from clearfront.brightdata import _clear_status_cache

    _clear_status_cache()
    yield
    _clear_status_cache()


# ---------------------------------------------------------------------------
# search_dorks_live
# ---------------------------------------------------------------------------


class TestSearchDorksLive:
    async def test_missing_api_key_returns_error_string(self, monkeypatch):
        monkeypatch.delenv("BRIGHTDATA_API_KEY", raising=False)
        monkeypatch.delenv("BRIGHTDATA_SERP_ZONE", raising=False)
        from clearfront.tools.search_dorks_live import run_dorks_live_osint

        result = await run_dorks_live_osint("john doe")
        assert "BRIGHTDATA_API_KEY" in result
        assert "5,000" in result
        assert "brightdata.com" in result

    async def test_missing_zone_returns_error_string(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.delenv("BRIGHTDATA_SERP_ZONE", raising=False)
        from clearfront.tools.search_dorks_live import run_dorks_live_osint

        result = await run_dorks_live_osint("john doe")
        assert "BRIGHTDATA_SERP_ZONE" in result
        assert "brightdata.com" in result

    async def test_does_not_raise_on_missing_key(self, monkeypatch):
        monkeypatch.delenv("BRIGHTDATA_API_KEY", raising=False)
        monkeypatch.delenv("BRIGHTDATA_SERP_ZONE", raising=False)
        from clearfront.tools.search_dorks_live import run_dorks_live_osint

        result = await run_dorks_live_osint("target")
        assert isinstance(result, str)

    async def test_empty_target_returns_error_string(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")
        from clearfront.tools.search_dorks_live import run_dorks_live_osint

        result = await run_dorks_live_osint("   ")
        assert "invalid" in result.lower() or "empty" in result.lower()

    async def test_success_returns_structured_results(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        # format="raw" + data_format="parsed_light": response.json() is the dict directly
        serp_payload = {
            "organic": [
                {
                    "title": "John Doe LinkedIn",
                    "link": "https://linkedin.com/in/johndoe",
                    "description": "Software engineer at Acme Corp.",
                },
            ]
        }
        mock_resp = _mock_serp_response(200, serp_payload)

        with patch("clearfront.tools.search_dorks_live.requests.post", return_value=mock_resp):
            from clearfront.tools.search_dorks_live import run_dorks_live_osint

            result = await run_dorks_live_osint("john doe", max_dorks=1)

        assert "John Doe LinkedIn" in result
        assert "linkedin.com/in/johndoe" in result
        assert "Software engineer" in result

    async def test_success_result_contains_dork_header(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        mock_resp = _mock_serp_response(200, {"organic": []})
        with patch("clearfront.tools.search_dorks_live.requests.post", return_value=mock_resp):
            from clearfront.tools.search_dorks_live import run_dorks_live_osint

            result = await run_dorks_live_osint("example.com", max_dorks=1)

        assert "[+] Dork:" in result

    async def test_no_organic_results_shows_placeholder(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        mock_resp = _mock_serp_response(200, {"organic": []})
        with patch("clearfront.tools.search_dorks_live.requests.post", return_value=mock_resp):
            from clearfront.tools.search_dorks_live import run_dorks_live_osint

            result = await run_dorks_live_osint("target", max_dorks=1)

        assert "no organic results" in result

    async def test_organic_link_field_used_as_url(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        mock_resp = _mock_serp_response(
            200,
            {
                "organic": [
                    {"title": "T", "link": "https://primary-link.com", "description": ""},
                ]
            },
        )
        with patch("clearfront.tools.search_dorks_live.requests.post", return_value=mock_resp):
            from clearfront.tools.search_dorks_live import run_dorks_live_osint

            result = await run_dorks_live_osint("target", max_dorks=1)

        assert "primary-link.com" in result

    async def test_request_uses_format_raw_not_json(self, monkeypatch):
        """Verify the outbound request body uses format=raw to prevent envelope wrapping."""
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        mock_resp = _mock_serp_response(200, {"organic": []})
        with patch(
            "clearfront.tools.search_dorks_live.requests.post", return_value=mock_resp
        ) as mock_post:
            from clearfront.tools.search_dorks_live import run_dorks_live_osint

            await run_dorks_live_osint("target", max_dorks=1)

        call_kwargs = mock_post.call_args.kwargs
        payload = call_kwargs.get("json", {})
        assert payload.get("format") == "raw", "Must use format=raw to avoid double-parse"
        assert payload.get("data_format") == "parsed_light"

    async def test_http_401_returns_auth_error(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "bad-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        mock_resp = _mock_serp_response(401)
        with patch("clearfront.tools.search_dorks_live.requests.post", return_value=mock_resp):
            from clearfront.tools.search_dorks_live import run_dorks_live_osint

            result = await run_dorks_live_osint("target", max_dorks=1)

        assert "invalid api key" in result.lower() or "error" in result.lower()

    async def test_http_429_returns_rate_limit_error(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        mock_resp = _mock_serp_response(429)
        with patch("clearfront.tools.search_dorks_live.requests.post", return_value=mock_resp):
            from clearfront.tools.search_dorks_live import run_dorks_live_osint

            result = await run_dorks_live_osint("target", max_dorks=1)

        assert "rate limit" in result.lower() or "error" in result.lower()

    async def test_all_requests_fail_returns_scan_error(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        mock_resp = _mock_serp_response(500)
        with patch("clearfront.tools.search_dorks_live.requests.post", return_value=mock_resp):
            from clearfront.tools.search_dorks_live import run_dorks_live_osint

            result = await run_dorks_live_osint("target", max_dorks=2)

        assert "Scan error" in result

    async def test_network_exception_handled_gracefully(self, monkeypatch):
        import requests as _requests

        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        with patch(
            "clearfront.tools.search_dorks_live.requests.post",
            side_effect=_requests.RequestException("connection refused"),
        ):
            from clearfront.tools.search_dorks_live import run_dorks_live_osint

            result = await run_dorks_live_osint("target", max_dorks=1)

        assert isinstance(result, str)
        assert "error" in result.lower()


# ---------------------------------------------------------------------------
# scrape_url
# ---------------------------------------------------------------------------


class TestScrapeUrl:
    async def test_missing_api_key_returns_error_string(self, monkeypatch):
        monkeypatch.delenv("BRIGHTDATA_API_KEY", raising=False)
        monkeypatch.delenv("BRIGHTDATA_UNLOCKER_ZONE", raising=False)
        from clearfront.tools.scrape_url import run_scrape_url_osint

        result = await run_scrape_url_osint("https://example.com")
        assert "BRIGHTDATA_API_KEY" in result
        assert "5,000" in result
        assert "brightdata.com" in result

    async def test_missing_zone_returns_error_string(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.delenv("BRIGHTDATA_UNLOCKER_ZONE", raising=False)
        from clearfront.tools.scrape_url import run_scrape_url_osint

        result = await run_scrape_url_osint("https://example.com")
        assert "BRIGHTDATA_UNLOCKER_ZONE" in result
        assert "brightdata.com" in result

    async def test_does_not_raise_on_missing_key(self, monkeypatch):
        monkeypatch.delenv("BRIGHTDATA_API_KEY", raising=False)
        monkeypatch.delenv("BRIGHTDATA_UNLOCKER_ZONE", raising=False)
        from clearfront.tools.scrape_url import run_scrape_url_osint

        result = await run_scrape_url_osint("https://example.com")
        assert isinstance(result, str)

    async def test_invalid_url_returns_error_string(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")
        from clearfront.tools.scrape_url import run_scrape_url_osint

        result = await run_scrape_url_osint("not-a-url")
        assert "Invalid URL" in result

    async def test_success_returns_markdown_content(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        # format="raw": response.text IS the markdown string, no JSON envelope
        markdown_body = "# Example Domain\n\nThis domain is for illustrative examples."
        mock_resp = _mock_unlocker_response(200, text=markdown_body)

        with patch("clearfront.tools.scrape_url.requests.post", return_value=mock_resp):
            from clearfront.tools.scrape_url import run_scrape_url_osint

            result = await run_scrape_url_osint("https://example.com")

        assert "# Example Domain" in result
        assert "[Web Unlocker] URL: https://example.com" in result
        # No Remote status line, format=raw returns no envelope
        assert "Remote status" not in result

    async def test_success_result_contains_url_header(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        mock_resp = _mock_unlocker_response(200, text="some markdown content")
        with patch("clearfront.tools.scrape_url.requests.post", return_value=mock_resp):
            from clearfront.tools.scrape_url import run_scrape_url_osint

            result = await run_scrape_url_osint("https://example.com")

        assert "[Web Unlocker] URL: https://example.com" in result
        assert "some markdown content" in result

    async def test_empty_body_is_an_error_not_content(self, monkeypatch):
        """A suspended account answers HTTP 200 with a blank body. Never report that as a scrape."""
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        mock_resp = _mock_unlocker_response(200, text="")
        with patch("clearfront.tools.scrape_url.requests.post", return_value=mock_resp):
            with patch(
                "clearfront.brightdata.requests.get",
                return_value=_mock_status_response(200, {"can_make_requests": True}),
            ):
                from clearfront.tools.scrape_url import run_scrape_url_osint

                result = await run_scrape_url_osint("https://example.com")

        assert "Scan error" in result
        assert "empty body" in result
        assert "No data was collected" in result

    async def test_suspended_account_named_in_error(self, monkeypatch):
        """The status endpoint knows the real reason. Surface it instead of a blank page."""
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        status_body = {"status": "suspended", "can_make_requests": False}
        with patch(
            "clearfront.tools.scrape_url.requests.post",
            return_value=_mock_unlocker_response(200, text=""),
        ):
            with patch(
                "clearfront.brightdata.requests.get",
                return_value=_mock_status_response(200, status_body),
            ):
                from clearfront.tools.scrape_url import run_scrape_url_osint

                result = await run_scrape_url_osint("https://example.com")

        assert "suspended" in result
        assert "cannot make requests" in result
        assert "brightdata.com/cp" in result

    async def test_whitespace_only_body_is_an_error(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        with patch(
            "clearfront.tools.scrape_url.requests.post",
            return_value=_mock_unlocker_response(200, text="   \n  \n"),
        ):
            with patch(
                "clearfront.brightdata.requests.get",
                return_value=_mock_status_response(200, {"can_make_requests": True}),
            ):
                from clearfront.tools.scrape_url import run_scrape_url_osint

                result = await run_scrape_url_osint("https://example.com")

        assert "Scan error" in result

    async def test_request_uses_format_raw_not_json(self, monkeypatch):
        """Verify the outbound request body uses format=raw to avoid JSON envelope parsing."""
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        mock_resp = _mock_unlocker_response(200, text="content")
        with patch("clearfront.tools.scrape_url.requests.post", return_value=mock_resp) as mock_post:
            from clearfront.tools.scrape_url import run_scrape_url_osint

            await run_scrape_url_osint("https://example.com")

        call_kwargs = mock_post.call_args.kwargs
        payload = call_kwargs.get("json", {})
        assert payload.get("format") == "raw", "Must use format=raw to avoid envelope parsing"
        assert payload.get("data_format") == "markdown"

    async def test_http_401_returns_auth_error(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "bad-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        mock_resp = _mock_unlocker_response(401)
        with patch("clearfront.tools.scrape_url.requests.post", return_value=mock_resp):
            from clearfront.tools.scrape_url import run_scrape_url_osint

            result = await run_scrape_url_osint("https://example.com")

        assert "invalid api key" in result.lower() or "scan error" in result.lower()

    async def test_http_403_returns_forbidden_error(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        mock_resp = _mock_unlocker_response(403)
        with patch("clearfront.tools.scrape_url.requests.post", return_value=mock_resp):
            from clearfront.tools.scrape_url import run_scrape_url_osint

            result = await run_scrape_url_osint("https://example.com")

        assert "forbidden" in result.lower() or "scan error" in result.lower()

    async def test_http_429_returns_rate_limit_error(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        mock_resp = _mock_unlocker_response(429)
        with patch("clearfront.tools.scrape_url.requests.post", return_value=mock_resp):
            from clearfront.tools.scrape_url import run_scrape_url_osint

            result = await run_scrape_url_osint("https://example.com")

        assert "rate limit" in result.lower() or "scan error" in result.lower()

    async def test_http_500_returns_error(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        mock_resp = _mock_unlocker_response(500)
        with patch("clearfront.tools.scrape_url.requests.post", return_value=mock_resp):
            from clearfront.tools.scrape_url import run_scrape_url_osint

            result = await run_scrape_url_osint("https://example.com")

        assert "error" in result.lower()

    async def test_network_exception_handled_gracefully(self, monkeypatch):
        import requests as _requests

        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_UNLOCKER_ZONE", "web_unlocker1")

        with patch(
            "clearfront.tools.scrape_url.requests.post",
            side_effect=_requests.RequestException("timeout"),
        ):
            from clearfront.tools.scrape_url import run_scrape_url_osint

            result = await run_scrape_url_osint("https://example.com")

        assert isinstance(result, str)
        assert "error" in result.lower()


# ---------------------------------------------------------------------------
# Empty HTTP 200: the suspended-account signature
# ---------------------------------------------------------------------------


class TestEmptyBodyOnSerp:
    """A suspended account returns HTTP 200 with a zero-length body on the SERP zone too."""

    async def test_dorks_live_empty_body_names_suspension(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        empty = _mock_unlocker_response(200, text="")
        status = _mock_status_response(200, {"status": "suspended", "can_make_requests": False})
        with patch("clearfront.tools.search_dorks_live.requests.post", return_value=empty):
            with patch("clearfront.brightdata.requests.get", return_value=status):
                from clearfront.tools.search_dorks_live import run_dorks_live_osint

                result = await run_dorks_live_osint("target", max_dorks=2)

        assert "suspended" in result
        # The old aggregate blamed the user's credentials for a backend outage.
        assert "Check your SERP backend credentials" not in result

    async def test_dorks_live_empty_body_does_not_raise_json_error(self, monkeypatch):
        """The pre-fix symptom was a raw 'Expecting value: line 1 column 1' parse error."""
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")

        empty = MagicMock()
        empty.status_code = 200
        empty.text = ""
        empty.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")
        status = _mock_status_response(200, {"can_make_requests": True})

        with patch("clearfront.tools.search_dorks_live.requests.post", return_value=empty):
            with patch("clearfront.brightdata.requests.get", return_value=status):
                from clearfront.tools.search_dorks_live import run_dorks_live_osint

                result = await run_dorks_live_osint("target", max_dorks=1)

        assert "Expecting value" not in result
        assert "empty body" in result

    async def test_footprint_empty_body_names_suspension(self, monkeypatch):
        monkeypatch.setenv("BRIGHTDATA_API_KEY", "test-key")
        monkeypatch.setenv("BRIGHTDATA_SERP_ZONE", "serp_api1")
        monkeypatch.delenv("SERPER_API_KEY", raising=False)

        empty = _mock_unlocker_response(200, text="")
        status = _mock_status_response(200, {"status": "suspended", "can_make_requests": False})
        with patch("clearfront.tools.search_footprint.requests.post", return_value=empty):
            with patch("clearfront.brightdata.requests.get", return_value=status):
                from clearfront.tools.search_footprint import run_footprint_osint

                result = await run_footprint_osint("aquassist_ian")

        assert "suspended" in result
        assert "Check your SERP backend credentials" not in result


class TestAccountBlockedReason:
    def test_returns_none_when_account_is_healthy(self):
        from clearfront.brightdata import account_blocked_reason

        status = _mock_status_response(200, {"status": "active", "can_make_requests": True})
        with patch("clearfront.brightdata.requests.get", return_value=status):
            assert account_blocked_reason("test-key") is None

    def test_returns_reason_when_account_cannot_make_requests(self):
        from clearfront.brightdata import account_blocked_reason

        status = _mock_status_response(200, {"status": "suspended", "can_make_requests": False})
        with patch("clearfront.brightdata.requests.get", return_value=status):
            reason = account_blocked_reason("test-key")

        assert reason is not None
        assert "suspended" in reason
        assert "brightdata.com/cp" in reason

    def test_returns_none_without_an_api_key(self):
        from clearfront.brightdata import account_blocked_reason

        assert account_blocked_reason("") is None

    def test_probe_failure_is_not_fatal(self):
        """A failed probe must not mask the caller's own error."""
        import requests as _requests

        from clearfront.brightdata import account_blocked_reason

        with patch(
            "clearfront.brightdata.requests.get",
            side_effect=_requests.RequestException("connection refused"),
        ):
            assert account_blocked_reason("test-key") is None

    def test_result_is_cached_per_key(self):
        """A failing sweep probes once, not once per tool call."""
        from clearfront.brightdata import account_blocked_reason

        status = _mock_status_response(200, {"status": "suspended", "can_make_requests": False})
        with patch("clearfront.brightdata.requests.get", return_value=status) as mock_get:
            for _ in range(5):
                account_blocked_reason("test-key")

        assert mock_get.call_count == 1

    def test_empty_body_reason_falls_back_when_status_is_silent(self):
        from clearfront.brightdata import empty_body_reason

        status = _mock_status_response(200, {"can_make_requests": True})
        with patch("clearfront.brightdata.requests.get", return_value=status):
            reason = empty_body_reason("test-key", "Bright Data SERP")

        assert "Bright Data SERP" in reason
        assert "empty body" in reason
        assert "No data was collected" in reason
