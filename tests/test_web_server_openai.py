# tests/test_web_server_openai.py
"""
Unit tests for the OpenAI-compatible paths in clearfront/web_server.py:
  - _select_chat_backend   (precedence matrix / Ollama regression guard)
  - _stream_openai         (SSE output, tool handling, error paths)

All HTTP calls are mocked, no live endpoint required.
Follows the same fixture and mocking conventions as test_web_server.py.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers (mirrors test_web_server.py conventions)
# ---------------------------------------------------------------------------


def _mock_requests_response(status_code: int = 200, body: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    body = body or {}
    resp.text = json.dumps(body)[:300]
    resp.json.return_value = body
    return resp


async def _collect(gen) -> list[dict]:
    items: list[dict] = []
    async for item in gen:
        items.append(item)
    return items


# ---------------------------------------------------------------------------
# _select_chat_backend, precedence matrix
# ---------------------------------------------------------------------------


class TestSelectChatBackend:
    """Full precedence matrix, also serves as regression guard for Ollama users."""

    # explicit UI selection always wins

    def test_explicit_openai_selection_returns_openai(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        from clearfront.web_server import ChatRequest, _select_chat_backend

        req = ChatRequest(message="hi", model="openai")
        assert _select_chat_backend(req) == "openai"

    def test_explicit_ollama_selection_returns_ollama(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-real-key")
        from clearfront.web_server import ChatRequest, _select_chat_backend

        req = ChatRequest(message="hi", model="ollama")
        assert _select_chat_backend(req) == "ollama"

    def test_explicit_openai_wins_even_with_anthropic_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-real-key")
        from clearfront.web_server import ChatRequest, _select_chat_backend

        req = ChatRequest(message="hi", model="openai")
        assert _select_chat_backend(req) == "openai"

    # model="claude" auto-detect paths

    def test_claude_model_with_anthropic_key_returns_claude(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-real-key")
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        from clearfront.web_server import ChatRequest, _select_chat_backend

        req = ChatRequest(message="hi", model="claude")
        assert _select_chat_backend(req) == "claude"

    def test_no_anthropic_key_openai_base_url_env_returns_openai(self, monkeypatch):
        """Key Ollama regression: OPENAI_BASE_URL env takes precedence over Ollama."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:4000/v1")
        from clearfront.web_server import ChatRequest, _select_chat_backend

        req = ChatRequest(message="hi", model="claude", ollama_host="http://localhost:11434")
        assert _select_chat_backend(req) == "openai"

    def test_openai_base_url_in_request_body_triggers_openai(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        from clearfront.web_server import ChatRequest, _select_chat_backend

        req = ChatRequest(
            message="hi",
            model="claude",
            openai_base_url="http://localhost:4000/v1",
            ollama_host="http://localhost:11434",
        )
        assert _select_chat_backend(req) == "openai"

    def test_ollama_only_user_not_broken(self, monkeypatch):
        """Core Ollama regression guard: no keys, no OPENAI_BASE_URL → ollama."""
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        from clearfront.web_server import ChatRequest, _select_chat_backend

        req = ChatRequest(message="hi", model="claude", ollama_host="http://localhost:11434")
        assert _select_chat_backend(req) == "ollama"

    def test_no_keys_no_openai_url_no_ollama_host_falls_back_to_claude(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        from clearfront.web_server import ChatRequest, _select_chat_backend

        req = ChatRequest(message="hi", model="claude", ollama_host="")
        assert _select_chat_backend(req) == "claude"

    def test_anthropic_key_wins_over_openai_env_in_auto_detect(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-real-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:4000/v1")
        from clearfront.web_server import ChatRequest, _select_chat_backend

        req = ChatRequest(message="hi", model="claude")
        assert _select_chat_backend(req) == "claude"

    def test_whitespace_only_anthropic_key_treated_as_absent(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "   ")
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        from clearfront.web_server import ChatRequest, _select_chat_backend

        req = ChatRequest(message="hi", model="claude", ollama_host="http://localhost:11434")
        assert _select_chat_backend(req) == "ollama"

    def test_unknown_model_with_anthropic_key_auto_detects_claude(self, monkeypatch):
        """Auto-detect fallback: any non-standard model value + Anthropic key → claude."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-real-key")
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        from clearfront.web_server import ChatRequest, _select_chat_backend

        # A model value that falls through all three explicit checks.
        req = ChatRequest(message="hi", model="unknown-future-model")
        assert _select_chat_backend(req) == "claude"


# ---------------------------------------------------------------------------
# _stream_openai, happy path
# ---------------------------------------------------------------------------


class TestStreamOpenaiNormalResponse:
    async def test_plain_reply_yields_text_then_done(self):
        from clearfront.web_server import _stream_openai

        body = {"choices": [{"message": {"content": "Hello!", "tool_calls": []}}]}
        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.return_value = _mock_requests_response(body=body)
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "hi"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        types = [e["type"] for e in events]
        assert types == ["text", "done"]
        assert events[0]["content"] == "Hello!"

    async def test_null_content_yields_done_only(self):
        from clearfront.web_server import _stream_openai

        body = {"choices": [{"message": {"content": None, "tool_calls": []}}]}
        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.return_value = _mock_requests_response(body=body)
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "hi"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        types = [e["type"] for e in events]
        assert "done" in types
        assert "text" not in types

    async def test_api_key_sent_as_bearer_header(self):
        from clearfront.web_server import _stream_openai

        body = {"choices": [{"message": {"content": "ok", "tool_calls": []}}]}
        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.return_value = _mock_requests_response(body=body)
                await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "hi"}],
                        "http://localhost:4000/v1",
                        "my-secret-key",
                        "gpt-4o-mini",
                    )
                )

        headers = mreq.post.call_args.kwargs["headers"]
        assert headers.get("Authorization") == "Bearer my-secret-key"

    async def test_no_api_key_omits_authorization_header(self):
        from clearfront.web_server import _stream_openai

        body = {"choices": [{"message": {"content": "ok", "tool_calls": []}}]}
        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.return_value = _mock_requests_response(body=body)
                await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "hi"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        headers = mreq.post.call_args.kwargs["headers"]
        assert "Authorization" not in headers


# ---------------------------------------------------------------------------
# _stream_openai, error paths
# ---------------------------------------------------------------------------


class TestStreamOpenaiErrors:
    async def test_http_400_yields_error_event(self):
        from clearfront.web_server import _stream_openai

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.return_value = _mock_requests_response(
                    status_code=400, body={"error": "bad request"}
                )
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "hi"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        assert len(events) == 1
        assert events[0]["type"] == "error"
        assert "400" in events[0]["message"]

    async def test_http_500_yields_error_event(self):
        from clearfront.web_server import _stream_openai

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.return_value = _mock_requests_response(status_code=500)
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "hi"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        assert events[0]["type"] == "error"
        assert "500" in events[0]["message"]

    async def test_connection_error_yields_error_event(self):
        from clearfront.web_server import _stream_openai

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.side_effect = ConnectionError("connection refused")
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "hi"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        assert events[0]["type"] == "error"

    async def test_empty_choices_yields_descriptive_error(self):
        """_stream_openai guards empty choices with a clear message (unlike agent.py)."""
        from clearfront.web_server import _stream_openai

        body = {"choices": []}
        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.return_value = _mock_requests_response(body=body)
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "hi"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        assert events[0]["type"] == "error"
        assert "no choices" in events[0]["message"].lower()

    async def test_error_path_emits_no_done_event(self):
        from clearfront.web_server import _stream_openai

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.return_value = _mock_requests_response(status_code=503)
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "hi"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        assert "done" not in [e["type"] for e in events]


# ---------------------------------------------------------------------------
# _stream_openai, tool call path
# ---------------------------------------------------------------------------


class TestStreamOpenaiToolCalls:
    def _two_call_side_effect(self, first: dict, second: dict):
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            return _mock_requests_response(body=first if call_count == 1 else second)

        return side_effect

    async def test_tool_call_yields_tool_events_then_text_then_done(self):
        from clearfront.web_server import _stream_openai

        first = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "function": {
                                    "name": "generate_dorks",
                                    "arguments": json.dumps({"input": "example.com"}),
                                },
                            }
                        ],
                    }
                }
            ]
        }
        second = {
            "choices": [{"message": {"content": "Investigation complete.", "tool_calls": []}}]
        }

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.side_effect = self._two_call_side_effect(first, second)
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "dorks for example.com"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        types = [e["type"] for e in events]
        assert "tool_start" in types
        assert "tool_result" in types
        assert "text" in types
        assert types[-1] == "done"

    async def test_tool_start_carries_correct_tool_name(self):
        from clearfront.web_server import _stream_openai

        first = {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "c1",
                                "function": {
                                    "name": "search_whois",
                                    "arguments": json.dumps({"input": "example.com"}),
                                },
                            }
                        ],
                    }
                }
            ]
        }
        second = {"choices": [{"message": {"content": "Done.", "tool_calls": []}}]}

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.side_effect = self._two_call_side_effect(first, second)
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "whois check"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        start = next(e for e in events if e["type"] == "tool_start")
        assert start["tool"] == "search_whois"

    async def test_assistant_message_before_tool_results_in_history(self):
        """assistant turn (with tool_calls) must precede tool result messages."""
        from clearfront.web_server import _stream_openai

        tool_calls_payload = [
            {
                "id": "call-1",
                "function": {
                    "name": "generate_dorks",
                    "arguments": json.dumps({"input": "example.com"}),
                },
            }
        ]
        first = {"choices": [{"message": {"content": "", "tool_calls": tool_calls_payload}}]}
        second = {"choices": [{"message": {"content": "Done.", "tool_calls": []}}]}

        captured: list[dict] = []
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                captured.extend(kwargs.get("json", {}).get("messages", []))
            return _mock_requests_response(body=first if call_count == 1 else second)

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.side_effect = side_effect
                await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "query"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        roles = [m["role"] for m in captured]
        assistant_idx = next(i for i, r in enumerate(roles) if r == "assistant")
        tool_idx = next(i for i, r in enumerate(roles) if r == "tool")
        assert assistant_idx < tool_idx

    async def test_fallback_argument_key_extraction(self):
        """When model uses 'query' instead of 'input', fallback extracts the value."""
        from clearfront.web_server import _stream_openai

        first = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "c1",
                                "function": {
                                    "name": "generate_dorks",
                                    "arguments": json.dumps({"query": "example.com"}),
                                },
                            }
                        ],
                    }
                }
            ]
        }
        second = {"choices": [{"message": {"content": "Done.", "tool_calls": []}}]}

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.side_effect = self._two_call_side_effect(first, second)
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "check example.com"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        start = next(e for e in events if e["type"] == "tool_start")
        assert start["input"] == "example.com"

    async def test_tool_result_event_carries_elapsed_time(self):
        from clearfront.web_server import _stream_openai

        first = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "c1",
                                "function": {
                                    "name": "generate_dorks",
                                    "arguments": json.dumps({"input": "example.com"}),
                                },
                            }
                        ],
                    }
                }
            ]
        }
        second = {"choices": [{"message": {"content": "Done.", "tool_calls": []}}]}

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.side_effect = self._two_call_side_effect(first, second)
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "query"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        result_evt = next(e for e in events if e["type"] == "tool_result")
        assert "elapsed" in result_evt
        assert isinstance(result_evt["elapsed"], float)

    async def test_invalid_json_tool_arguments_use_input_fallback(self):
        """When tool argument JSON is malformed, fallback wraps it in {'input': raw}."""
        from clearfront.web_server import _stream_openai

        first = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "c1",
                                "function": {
                                    "name": "generate_dorks",
                                    "arguments": "NOT VALID JSON {{{",
                                },
                            }
                        ],
                    }
                }
            ]
        }
        second = {"choices": [{"message": {"content": "Done.", "tool_calls": []}}]}

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.post.side_effect = self._two_call_side_effect(first, second)
                events = await _collect(
                    _stream_openai(
                        [{"role": "user", "content": "query"}],
                        "http://localhost:4000/v1",
                        "",
                        "gpt-4o-mini",
                    )
                )

        # Must not crash, tool_start should still be emitted.
        types = [e["type"] for e in events]
        assert "tool_start" in types


# ---------------------------------------------------------------------------
# _stream_openai, httpx code path
# ---------------------------------------------------------------------------


class TestStreamOpenaiHttpxPath:
    """Tests for the httpx branch (when _httpx is not None)."""

    async def test_httpx_plain_reply_yields_text_then_done(self):
        """When httpx is available it is used instead of requests."""
        from clearfront.web_server import _stream_openai

        body = {"choices": [{"message": {"content": "httpx reply", "tool_calls": []}}]}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = body
        mock_response.text = ""

        mock_httpx = MagicMock()
        mock_client_instance = MagicMock()
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client_instance.post = AsyncMock(return_value=mock_response)
        mock_httpx.AsyncClient.return_value = mock_client_instance

        with patch("clearfront.web_server._httpx", mock_httpx):
            events = await _collect(
                _stream_openai(
                    [{"role": "user", "content": "hi"}],
                    "http://localhost:4000/v1",
                    "",
                    "gpt-4o-mini",
                )
            )

        types = [e["type"] for e in events]
        assert "text" in types
        assert types[-1] == "done"
        text_evt = next(e for e in events if e["type"] == "text")
        assert text_evt["content"] == "httpx reply"

    async def test_httpx_non_200_yields_error(self):
        from clearfront.web_server import _stream_openai

        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.text = "service unavailable"

        mock_httpx = MagicMock()
        mock_client_instance = MagicMock()
        mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
        mock_client_instance.__aexit__ = AsyncMock(return_value=False)
        mock_client_instance.post = AsyncMock(return_value=mock_response)
        mock_httpx.AsyncClient.return_value = mock_client_instance

        with patch("clearfront.web_server._httpx", mock_httpx):
            events = await _collect(
                _stream_openai(
                    [{"role": "user", "content": "hi"}],
                    "http://localhost:4000/v1",
                    "",
                    "gpt-4o-mini",
                )
            )

        assert events[0]["type"] == "error"
        assert "503" in events[0]["message"]


# ---------------------------------------------------------------------------
# _probe_openai_endpoint, server-side connectivity probe
# ---------------------------------------------------------------------------


class TestProbeOpenaiEndpoint:
    """Probe must distinguish unreachable / reachable-but-unauthorized / ok.

    Regression guard for the PR #8 bug where a healthy LiteLLM/vLLM proxy that
    returns 401 on /models was reported as backend 'none' (unreachable),
    blocking chat even though the endpoint was up.
    """

    async def test_empty_base_url_is_unreachable(self):
        from clearfront.web_server import _probe_openai_endpoint

        result = await _probe_openai_endpoint("", "")
        assert result == {"reachable": False, "auth_ok": False, "status_code": None}

    async def test_200_is_reachable_and_auth_ok(self):
        from clearfront.web_server import _probe_openai_endpoint

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.get.return_value = _mock_requests_response(status_code=200, body={"data": []})
                result = await _probe_openai_endpoint("http://localhost:4000/v1", "sk-key")

        assert result["reachable"] is True
        assert result["auth_ok"] is True
        assert result["status_code"] == 200

    async def test_401_is_reachable_but_not_auth_ok(self):
        from clearfront.web_server import _probe_openai_endpoint

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.get.return_value = _mock_requests_response(status_code=401, body={"error": "bad key"})
                result = await _probe_openai_endpoint("http://localhost:4000/v1", "sk-stale")

        assert result["reachable"] is True
        assert result["auth_ok"] is False
        assert result["status_code"] == 401

    async def test_connection_error_is_unreachable(self):
        from clearfront.web_server import _probe_openai_endpoint

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.get.side_effect = ConnectionError("refused")
                result = await _probe_openai_endpoint("http://10.0.0.9:4000/v1", "")

        assert result["reachable"] is False
        assert result["auth_ok"] is False
        assert result["status_code"] is None

    async def test_bearer_header_sent_when_key_present(self):
        from clearfront.web_server import _probe_openai_endpoint

        with patch("clearfront.web_server._httpx", None):
            with patch("clearfront.web_server._requests") as mreq:
                mreq.get.return_value = _mock_requests_response(status_code=200, body={})
                await _probe_openai_endpoint("http://localhost:4000/v1", "sk-abc")

        _, kwargs = mreq.get.call_args
        assert kwargs["headers"]["Authorization"] == "Bearer sk-abc"


# ---------------------------------------------------------------------------
# OpenAITestRequest, body model for POST /api/openai/test
# ---------------------------------------------------------------------------


class TestOpenAITestRequestModel:
    """Regression guard: the /api/openai/test body must NOT require a 'message'
    field. It originally reused ChatRequest (message required), so the Settings
    'Test connection' POST returned 422."""

    def test_validates_with_no_fields(self):
        from clearfront.web_server import OpenAITestRequest

        req = OpenAITestRequest()
        assert req.openai_base_url == ""
        assert req.openai_api_key == ""

    def test_accepts_partial_body(self):
        from clearfront.web_server import OpenAITestRequest

        req = OpenAITestRequest(openai_base_url="http://localhost:4000/v1")
        assert req.openai_base_url == "http://localhost:4000/v1"
        assert req.openai_api_key == ""
