"""Tests for empty-response fallback via configured fallbackModels."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from nanobot.agent.runner import AgentRunner, AgentRunSpec
from nanobot.config.schema import AgentDefaults
from nanobot.providers.base import LLMResponse
from nanobot.providers.fallback_provider import FallbackProvider
from nanobot.utils.runtime import EMPTY_FINAL_RESPONSE_MESSAGE
from tests.agent.test_runner_fallback import _FakeProvider, _fallback, _make_response

_MAX_TOOL_RESULT_CHARS = AgentDefaults().max_tool_result_chars


def _empty_response() -> LLMResponse:
    return _make_response(content="")


@pytest.mark.asyncio
async def test_runner_empty_response_uses_fallback_before_finalization() -> None:
    """After primary empty retries, first successful fallback wins without finalization."""
    primary = _FakeProvider("primary", _empty_response())
    fallback = _FakeProvider("fallback", _make_response("fallback answer"))
    factory = MagicMock(return_value=fallback)
    provider = FallbackProvider(
        primary=primary,
        fallback_presets=[_fallback("fallback-a")],
        provider_factory=factory,
    )

    tools = MagicMock()
    tools.get_definitions.return_value = []

    runner = AgentRunner(provider)
    result = await runner.run(AgentRunSpec(
        initial_messages=[{"role": "user", "content": "do task"}],
        tools=tools,
        model="primary-model",
        max_iterations=3,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
    ))

    assert result.final_content == "fallback answer"
    assert result.stop_reason == "completed"
    assert len(primary.chat_calls) == 2
    assert factory.call_count == 1
    assert fallback.chat_calls[0]["model"] == "fallback-a"
    assert all(call.get("tools") is not None for call in primary.chat_calls)


@pytest.mark.asyncio
async def test_runner_empty_response_all_fallbacks_blank_then_finalization() -> None:
    """Blank fallbacks proceed to finalization; still empty yields empty_final_response."""
    primary = _FakeProvider("primary", _empty_response())
    fallback = _FakeProvider("fallback", _empty_response())
    factory = MagicMock(return_value=fallback)
    provider = FallbackProvider(
        primary=primary,
        fallback_presets=[_fallback("fallback-a")],
        provider_factory=factory,
    )

    tools = MagicMock()
    tools.get_definitions.return_value = []

    runner = AgentRunner(provider)
    result = await runner.run(AgentRunSpec(
        initial_messages=[{"role": "user", "content": "do task"}],
        tools=tools,
        model="primary-model",
        max_iterations=3,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
    ))

    assert result.final_content == EMPTY_FINAL_RESPONSE_MESSAGE
    assert result.stop_reason == "empty_final_response"
    assert len(primary.chat_calls) == 3
    assert factory.call_count == 2


@pytest.mark.asyncio
async def test_runner_empty_response_skips_fallback_when_content_streamed() -> None:
    """When user-visible content was already streamed, empty fallback is skipped."""
    primary = _FakeProvider("primary", _empty_response())

    async def chat_stream(self, **kwargs):
        on_delta = kwargs.get("on_content_delta")
        if on_delta:
            await on_delta("partial")
        return _empty_response()

    primary.chat_stream = chat_stream.__get__(primary, _FakeProvider)  # type: ignore[method-assign]

    fallback = _FakeProvider("fallback", _make_response("fallback answer"))
    factory = MagicMock(return_value=fallback)
    provider = FallbackProvider(
        primary=primary,
        fallback_presets=[_fallback("fallback-a")],
        provider_factory=factory,
    )

    tools = MagicMock()
    tools.get_definitions.return_value = []

    hook = MagicMock()
    hook.wants_streaming.return_value = True
    hook.finalize_content.side_effect = lambda _ctx, content: content
    hook.before_iteration = AsyncMock()
    hook.on_stream = AsyncMock()
    hook.on_stream_end = AsyncMock()
    hook.after_iteration = AsyncMock()
    hook.emit_reasoning = AsyncMock()
    hook.emit_reasoning_end = AsyncMock()

    runner = AgentRunner(provider)
    result = await runner.run(AgentRunSpec(
        initial_messages=[{"role": "user", "content": "do task"}],
        tools=tools,
        model="primary-model",
        max_iterations=3,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
        hook=hook,
    ))

    factory.assert_not_called()
    assert result.stop_reason == "empty_final_response"


@pytest.mark.asyncio
async def test_runner_empty_response_fallback_dispatches_tool_calls() -> None:
    """When the empty-response fallback returns tool calls, the runner must
    execute them in the same iteration instead of falling through to the
    empty-final-response path.

    Reproduces the production scenario where Kimi K2.6 emitted
    ``finish_reason=tool_calls`` with zero tool_calls and Haiku correctly
    proposed an ``edit_file`` tool call as the fallback.
    """
    from typing import Any

    from nanobot.providers.base import LLMProvider, ToolCallRequest

    primary_responses = [
        _empty_response(),  # iter 0: empty → silent retry
        _empty_response(),  # iter 1: empty → fallback → tool call
        _make_response("done"),  # iter 2: after tool result, final answer
    ]

    class _StatefulProvider(LLMProvider):
        def __init__(self, name: str, responses: list[LLMResponse]):
            super().__init__()
            self.name = name
            self._responses = list(responses)
            self.chat_calls: list[dict[str, Any]] = []

        def get_default_model(self) -> str:
            return f"{self.name}/model"

        async def chat(self, **kwargs: Any) -> LLMResponse:
            self.chat_calls.append(dict(kwargs))
            return (
                self._responses.pop(0)
                if self._responses
                else self._responses_last
            )

        @property
        def _responses_last(self) -> LLMResponse:
            return _empty_response()

        async def chat_stream(self, **kwargs: Any) -> LLMResponse:
            return await self.chat(**kwargs)

    primary = _StatefulProvider("primary", primary_responses)
    haiku_tool_response = LLMResponse(
        content="",
        tool_calls=[ToolCallRequest(id="tc1", name="read_file", arguments={"path": "a.txt"})],
        finish_reason="tool_calls",
    )
    haiku = _FakeProvider("haiku", haiku_tool_response)
    factory = MagicMock(return_value=haiku)
    provider = FallbackProvider(
        primary=primary,
        fallback_presets=[_fallback("haiku")],
        provider_factory=factory,
    )

    tools = MagicMock()
    tools.get_definitions.return_value = [{"type": "function", "function": {"name": "read_file"}}]
    tools.execute = AsyncMock(return_value="file content")

    runner = AgentRunner(provider)
    result = await runner.run(AgentRunSpec(
        initial_messages=[{"role": "user", "content": "do task"}],
        tools=tools,
        model="primary-model",
        max_iterations=5,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
    ))

    assert result.final_content == "done"
    assert result.stop_reason == "completed"
    # Tool was executed via the fallback's tool call.
    tools.execute.assert_awaited_once()
    assert "read_file" in result.tools_used
    # Persisted history should contain the assistant tool_calls turn and the
    # tool result, proving the redispatch path took effect.
    tool_msgs = [m for m in result.messages if m.get("role") == "tool"]
    assert len(tool_msgs) == 1
    assert tool_msgs[0]["tool_call_id"] == "tc1"


@pytest.mark.asyncio
async def test_finalization_fallback_uses_finalization_prompt_and_no_tools() -> None:
    """When primary finalization is empty, the fallback request must include
    the finalization prompt and NOT advertise tools — otherwise the fallback
    model will just propose another tool call instead of a final answer.
    """
    from nanobot.utils.runtime import FINALIZATION_RETRY_PROMPT

    primary = _FakeProvider("primary", _empty_response())
    fallback = _FakeProvider("fallback", _empty_response())
    factory = MagicMock(return_value=fallback)
    provider = FallbackProvider(
        primary=primary,
        fallback_presets=[_fallback("fallback-a")],
        provider_factory=factory,
    )

    tools = MagicMock()
    tools.get_definitions.return_value = [{"type": "function", "function": {"name": "read_file"}}]

    runner = AgentRunner(provider)
    await runner.run(AgentRunSpec(
        initial_messages=[{"role": "user", "content": "do task"}],
        tools=tools,
        model="primary-model",
        max_iterations=3,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
    ))

    # Fallback got two attempts: one for the empty-response fallback (tools
    # still on, this is the normal recovery path), and one for the
    # finalization fallback (tools must be off + finalization prompt present).
    assert len(fallback.chat_calls) == 2
    finalization_call = fallback.chat_calls[1]
    assert finalization_call.get("tools") is None, (
        "Finalization fallback must be sent with tools=None to discourage "
        "another tool call instead of a final answer"
    )
    last_user_msg = finalization_call["messages"][-1]
    assert last_user_msg.get("role") == "user"
    assert last_user_msg.get("content") == FINALIZATION_RETRY_PROMPT
