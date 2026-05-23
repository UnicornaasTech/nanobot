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
