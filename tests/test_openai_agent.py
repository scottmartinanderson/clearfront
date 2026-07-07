# tests/test_openai_agent.py
"""
Unit tests for OpenAICompatibleAgent (clearfront/agent.py).

All OpenAI SDK calls are mocked, no live endpoint required.
The openai package itself is not installed (it is an optional extra), so
every test injects a fake module via sys.modules.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers, build mock openai SDK objects
# ---------------------------------------------------------------------------


def _make_mock_openai() -> MagicMock:
    """Return a minimal mock of the openai package.

    No spec= so arbitrary attribute access (AsyncOpenAI, etc.) is allowed.
    Exception types are real classes so except-clause isinstance checks work.
    """
    mod = MagicMock()
    mod.AuthenticationError = type("AuthenticationError", (Exception,), {})
    mod.APIConnectionError = type("APIConnectionError", (Exception,), {})
    return mod


def _make_response(content: str, tool_calls: list | None = None) -> MagicMock:
    """Build a mock ChatCompletion response with one choice."""
    msg = MagicMock()
    msg.content = content
    msg.tool_calls = tool_calls
    choice = MagicMock()
    choice.message = msg
    resp = MagicMock()
    resp.choices = [choice]
    return resp


def _make_response_empty_choices() -> MagicMock:
    """Build a mock ChatCompletion response with no choices (edge-case)."""
    resp = MagicMock()
    resp.choices = []
    return resp


def _make_tool_call(tc_id: str, name: str, arguments: str) -> MagicMock:
    """Build a mock tool-call object."""
    tc = MagicMock()
    tc.id = tc_id
    tc.function.name = name
    tc.function.arguments = arguments
    return tc


# ---------------------------------------------------------------------------
# TestOpenAICompatibleAgentMissingDep
# ---------------------------------------------------------------------------


class TestOpenAICompatibleAgentMissingDep:
    """When the openai package is absent the agent must return a friendly error."""

    async def test_missing_openai_package_returns_error_response(self):
        from clearfront.agent import OpenAICompatibleAgent

        agent = OpenAICompatibleAgent()
        with patch.dict(sys.modules, {"openai": None}):
            result = await agent.run("investigate test@example.com")

        assert result.error != ""
        assert "openai" in result.error.lower()
        assert result.content == ""

    async def test_missing_package_error_includes_install_hint(self):
        from clearfront.agent import OpenAICompatibleAgent

        agent = OpenAICompatibleAgent()
        with patch.dict(sys.modules, {"openai": None}):
            result = await agent.run("investigate test@example.com")

        assert "pip install" in result.error


# ---------------------------------------------------------------------------
# TestOpenAICompatibleAgentHappyPath
# ---------------------------------------------------------------------------


class TestOpenAICompatibleAgentHappyPath:
    """No-tool-call responses are returned as clean AgentResponse objects."""

    async def test_plain_text_response_no_tools(self):
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(
            return_value=_make_response("Here is my report.", tool_calls=None)
        )

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent(model="test-model", base_url="http://localhost/v1")
            result = await agent.run("investigate example.com")

        assert result.content == "Here is my report."
        assert result.error == ""
        assert result.tool_calls == []

    async def test_prompt_is_sent_as_user_message(self):
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(return_value=_make_response("ok"))

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent()
            await agent.run("my special query")

        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        messages = call_kwargs["messages"]
        user_msgs = [m for m in messages if m["role"] == "user"]
        assert any("my special query" in m["content"] for m in user_msgs)

    async def test_system_prompt_is_first_message(self):
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(return_value=_make_response("ok"))

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent()
            await agent.run("query")

        messages = mock_client.chat.completions.create.call_args.kwargs["messages"]
        assert messages[0]["role"] == "system"

    async def test_response_stored_in_history(self):
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(return_value=_make_response("final answer"))

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent()
            await agent.run("query")
            roles = [m["role"] for m in agent.history]

        assert "user" in roles
        assert "assistant" in roles

    async def test_model_and_base_url_forwarded_to_sdk(self):
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(return_value=_make_response("ok"))

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent(model="custom-model", base_url="http://my-server/v1")
            await agent.run("query")

        mock_openai.AsyncOpenAI.assert_called_once_with(
            base_url="http://my-server/v1", api_key=agent.api_key
        )
        call_kwargs = mock_client.chat.completions.create.call_args.kwargs
        assert call_kwargs["model"] == "custom-model"


# ---------------------------------------------------------------------------
# TestOpenAICompatibleAgentToolUseLoop
# ---------------------------------------------------------------------------


class TestOpenAICompatibleAgentToolUseLoop:
    """The tool-use loop: tool_calls → execute → feed results back → terminate."""

    async def test_tool_call_executes_real_tool(self):
        """A response with tool_calls triggers _execute_tool and records the result."""
        from clearfront.agent import OpenAICompatibleAgent

        tc = _make_tool_call("call-1", "generate_dorks", json.dumps({"target": "example.com"}))
        first_resp = _make_response("", tool_calls=[tc])
        final_resp = _make_response("Investigation complete.", tool_calls=None)

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(side_effect=[first_resp, final_resp])

        with patch.dict(sys.modules, {"openai": mock_openai}):
            with patch(
                "clearfront.agent._execute_tool",
                new=AsyncMock(return_value="dork results here"),
            ):
                agent = OpenAICompatibleAgent()
                result = await agent.run("dorks for example.com")

        assert result.content == "Investigation complete."
        assert len(result.tool_calls) == 1
        assert result.tool_calls[0].name == "generate_dorks"
        assert result.tool_calls[0].result == "dork results here"

    async def test_assistant_message_appended_before_tool_result(self):
        """The assistant message (with tool_calls) must appear BEFORE the tool
        result message in ctx.messages, required by the OpenAI protocol."""
        from clearfront.agent import OpenAICompatibleAgent

        tc = _make_tool_call("call-1", "generate_dorks", json.dumps({"target": "example.com"}))
        first_resp = _make_response("thinking...", tool_calls=[tc])
        final_resp = _make_response("done", tool_calls=None)

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(side_effect=[first_resp, final_resp])

        with patch.dict(sys.modules, {"openai": mock_openai}):
            with patch("clearfront.agent._execute_tool", new=AsyncMock(return_value="result")):
                agent = OpenAICompatibleAgent()
                await agent.run("query")

        second_call_messages = mock_client.chat.completions.create.call_args_list[1].kwargs[
            "messages"
        ]
        roles = [m["role"] for m in second_call_messages]
        assistant_idx = next(i for i, r in enumerate(roles) if r == "assistant")
        tool_idx = next(i for i, r in enumerate(roles) if r == "tool")
        assert assistant_idx < tool_idx, (
            "assistant message must precede tool result in the messages list"
        )

    async def test_tool_result_carries_correct_tool_call_id(self):
        """Each tool result message must carry the matching tool_call_id."""
        from clearfront.agent import OpenAICompatibleAgent

        tc = _make_tool_call("my-id-42", "generate_dorks", json.dumps({"target": "t.com"}))
        first_resp = _make_response("", tool_calls=[tc])
        final_resp = _make_response("done", tool_calls=None)

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(side_effect=[first_resp, final_resp])

        with patch.dict(sys.modules, {"openai": mock_openai}):
            with patch("clearfront.agent._execute_tool", new=AsyncMock(return_value="r")):
                agent = OpenAICompatibleAgent()
                await agent.run("query")

        second_call_messages = mock_client.chat.completions.create.call_args_list[1].kwargs[
            "messages"
        ]
        tool_msgs = [m for m in second_call_messages if m["role"] == "tool"]
        assert len(tool_msgs) == 1
        assert tool_msgs[0]["tool_call_id"] == "my-id-42"
        assert tool_msgs[0]["content"] == "r"

    async def test_multiple_tool_calls_in_one_turn_all_executed(self):
        """When the model returns two tool_calls in one response both must run."""
        from clearfront.agent import OpenAICompatibleAgent

        tc1 = _make_tool_call("id-1", "generate_dorks", json.dumps({"target": "a.com"}))
        tc2 = _make_tool_call("id-2", "search_whois", json.dumps({"domain": "a.com"}))
        first_resp = _make_response("", tool_calls=[tc1, tc2])
        final_resp = _make_response("done", tool_calls=None)

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(side_effect=[first_resp, final_resp])

        execute_calls: list[str] = []

        async def _fake_execute(name, tool_input, on_tool_call, *_extra):
            execute_calls.append(name)
            return f"result:{name}"

        with patch.dict(sys.modules, {"openai": mock_openai}):
            with patch("clearfront.agent._execute_tool", side_effect=_fake_execute):
                agent = OpenAICompatibleAgent()
                result = await agent.run("investigate a.com")

        assert execute_calls == ["generate_dorks", "search_whois"]
        assert len(result.tool_calls) == 2

        second_call_messages = mock_client.chat.completions.create.call_args_list[1].kwargs[
            "messages"
        ]
        tool_msgs = [m for m in second_call_messages if m["role"] == "tool"]
        assert len(tool_msgs) == 2
        assert {m["tool_call_id"] for m in tool_msgs} == {"id-1", "id-2"}

    async def test_loop_terminates_on_final_no_tool_message(self):
        """After the tool round the loop must stop when no tool_calls are returned."""
        from clearfront.agent import OpenAICompatibleAgent

        tc = _make_tool_call("c1", "search_ip", json.dumps({"ip": "8.8.8.8"}))
        first_resp = _make_response("", tool_calls=[tc])
        final_resp = _make_response("IP belongs to Google.", tool_calls=None)

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(side_effect=[first_resp, final_resp])

        with patch.dict(sys.modules, {"openai": mock_openai}):
            with patch("clearfront.agent._execute_tool", new=AsyncMock(return_value="ok")):
                agent = OpenAICompatibleAgent()
                result = await agent.run("investigate 8.8.8.8")

        assert mock_client.chat.completions.create.call_count == 2
        assert result.content == "IP belongs to Google."
        assert result.error == ""

    async def test_tool_arguments_json_string_decoded_to_dict(self):
        """Arguments arriving as a JSON string are decoded to a dict before dispatch."""
        from clearfront.agent import OpenAICompatibleAgent

        args_str = json.dumps({"domain": "example.com"})
        tc = _make_tool_call("c1", "search_whois", args_str)
        first_resp = _make_response("", tool_calls=[tc])
        final_resp = _make_response("done", tool_calls=None)

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(side_effect=[first_resp, final_resp])

        captured: list[dict] = []

        async def _capture(name, tool_input, on_tool_call, *_extra):
            captured.append(tool_input)
            return "whois data"

        with patch.dict(sys.modules, {"openai": mock_openai}):
            with patch("clearfront.agent._execute_tool", side_effect=_capture):
                agent = OpenAICompatibleAgent()
                await agent.run("whois example.com")

        assert captured[0] == {"domain": "example.com"}

    async def test_on_tool_call_callback_forwarded(self):
        """The optional on_tool_call callback is forwarded through to _execute_tool."""
        from clearfront.agent import OpenAICompatibleAgent

        tc = _make_tool_call("c1", "generate_dorks", json.dumps({"target": "x.com"}))
        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(
            side_effect=[
                _make_response("", tool_calls=[tc]),
                _make_response("done"),
            ]
        )

        callback_calls: list[tuple] = []

        async def _fake_execute(name, tool_input, on_tool_call, *_extra):
            if on_tool_call:
                await on_tool_call(name, tool_input)
            return "ok"

        async def my_callback(name, inp):
            callback_calls.append((name, inp))

        with patch.dict(sys.modules, {"openai": mock_openai}):
            with patch("clearfront.agent._execute_tool", side_effect=_fake_execute):
                agent = OpenAICompatibleAgent()
                await agent.run("query", on_tool_call=my_callback)

        assert len(callback_calls) == 1
        assert callback_calls[0][0] == "generate_dorks"

    async def test_invalid_json_arguments_use_fallback(self):
        """When tool argument JSON is malformed, the fallback wraps it in {'input': raw}."""
        from clearfront.agent import OpenAICompatibleAgent

        tc = _make_tool_call("c1", "generate_dorks", "NOT VALID JSON {{{")
        first_resp = _make_response("", tool_calls=[tc])
        final_resp = _make_response("done", tool_calls=None)

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(side_effect=[first_resp, final_resp])

        captured: list[dict] = []

        async def _capture(name, tool_input, on_tool_call, *_extra):
            captured.append(tool_input)
            return "ok"

        with patch.dict(sys.modules, {"openai": mock_openai}):
            with patch("clearfront.agent._execute_tool", side_effect=_capture):
                agent = OpenAICompatibleAgent()
                await agent.run("query")

        # Fallback wraps the raw string under the "input" key.
        assert captured[0] == {"input": "NOT VALID JSON {{{"}


# ---------------------------------------------------------------------------
# TestOpenAICompatibleAgentEmptyChoices  (documents a known bug)
# ---------------------------------------------------------------------------


class TestOpenAICompatibleAgentEmptyChoices:
    """Empty choices list is caught early and returns a descriptive error."""

    async def test_empty_choices_returns_error_not_crash(self):
        """An empty choices list must not propagate an uncaught exception."""
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(return_value=_make_response_empty_choices())

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent()
            result = await agent.run("query")

        assert result.error != ""
        assert result.content == ""

    async def test_empty_choices_error_message_is_descriptive(self):
        """Error message tells the user the server returned no choices."""
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(return_value=_make_response_empty_choices())

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent(base_url="http://localhost/v1")
            result = await agent.run("query")

        assert "no choices" in result.error.lower()
        assert "list index out of range" not in result.error


# ---------------------------------------------------------------------------
# TestOpenAICompatibleAgentErrorHandling
# ---------------------------------------------------------------------------


class TestOpenAICompatibleAgentErrorHandling:
    """Auth, connection, and generic errors surface as non-crashing AgentResponse."""

    async def test_authentication_error_mentions_endpoint(self):
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(
            side_effect=mock_openai.AuthenticationError("bad key")
        )

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent(base_url="http://localhost/v1")
            result = await agent.run("query")

        assert result.error != ""
        assert result.content == ""
        assert "http://localhost/v1" in result.error

    async def test_connection_error_mentions_endpoint(self):
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(
            side_effect=mock_openai.APIConnectionError("no route")
        )

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent(base_url="http://nowhere/v1")
            result = await agent.run("query")

        assert result.error != ""
        assert result.content == ""
        assert "http://nowhere/v1" in result.error

    async def test_generic_exception_caught_and_returned_as_error(self):
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(
            side_effect=RuntimeError("unexpected kaboom")
        )

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent()
            result = await agent.run("query")

        assert result.error != ""
        assert result.content == ""


# ---------------------------------------------------------------------------
# TestOpenAICompatibleAgentHistory
# ---------------------------------------------------------------------------


class TestOpenAICompatibleAgentHistory:
    """clear_history resets state; multi-turn history accumulates correctly."""

    async def test_clear_history_empties_history(self):
        from clearfront.agent import OpenAICompatibleAgent

        mock_openai = _make_mock_openai()
        mock_client = MagicMock()
        mock_openai.AsyncOpenAI.return_value = mock_client
        mock_client.chat.completions.create = AsyncMock(return_value=_make_response("ok"))

        with patch.dict(sys.modules, {"openai": mock_openai}):
            agent = OpenAICompatibleAgent()
            await agent.run("first query")
            assert len(agent.history) > 0
            agent.clear_history()

        assert agent.history == []
