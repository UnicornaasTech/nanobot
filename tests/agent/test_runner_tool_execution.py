"""Tests for AgentRunner tool execution: batching, concurrency, exclusive tools."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from nanobot.agent.tools.base import Tool
from nanobot.agent.tools.registry import ToolRegistry
from nanobot.config.schema import AgentDefaults
from nanobot.providers.base import LLMResponse, ToolCallRequest

_MAX_TOOL_RESULT_CHARS = AgentDefaults().max_tool_result_chars


def _empty_tool_tracking() -> tuple[dict, dict, dict, dict, set, set, dict]:
    return {}, {}, {}, {}, set(), set(), {}

class _DelayTool(Tool):
    def __init__(
        self,
        name: str,
        *,
        delay: float,
        read_only: bool,
        shared_events: list[str],
        exclusive: bool = False,
    ):
        self._name = name
        self._delay = delay
        self._read_only = read_only
        self._shared_events = shared_events
        self._exclusive = exclusive

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return self._name

    @property
    def parameters(self) -> dict:
        return {"type": "object", "properties": {}, "required": []}

    @property
    def read_only(self) -> bool:
        return self._read_only

    @property
    def exclusive(self) -> bool:
        return self._exclusive

    async def execute(self, **kwargs):
        self._shared_events.append(f"start:{self._name}")
        await asyncio.sleep(self._delay)
        self._shared_events.append(f"end:{self._name}")
        return self._name


@pytest.mark.asyncio
async def test_runner_batches_read_only_tools_before_exclusive_work():
    from nanobot.agent.runner import AgentRunSpec, AgentRunner

    tools = ToolRegistry()
    shared_events: list[str] = []
    read_a = _DelayTool("read_a", delay=0.05, read_only=True, shared_events=shared_events)
    read_b = _DelayTool("read_b", delay=0.05, read_only=True, shared_events=shared_events)
    write_a = _DelayTool("write_a", delay=0.01, read_only=False, shared_events=shared_events)
    tools.register(read_a)
    tools.register(read_b)
    tools.register(write_a)

    runner = AgentRunner(MagicMock())
    await runner._execute_tools(
        AgentRunSpec(
            initial_messages=[],
            tools=tools,
            model="test-model",
            max_iterations=1,
            max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
            concurrent_tools=True,
        ),
        [
            ToolCallRequest(id="ro1", name="read_a", arguments={}),
            ToolCallRequest(id="ro2", name="read_b", arguments={}),
            ToolCallRequest(id="rw1", name="write_a", arguments={}),
        ],
        *_empty_tool_tracking(),
    )

    assert shared_events[0:2] == ["start:read_a", "start:read_b"]
    assert "end:read_a" in shared_events and "end:read_b" in shared_events
    assert shared_events.index("end:read_a") < shared_events.index("start:write_a")
    assert shared_events.index("end:read_b") < shared_events.index("start:write_a")
    assert shared_events[-2:] == ["start:write_a", "end:write_a"]


@pytest.mark.asyncio
async def test_runner_does_not_batch_exclusive_read_only_tools():
    from nanobot.agent.runner import AgentRunSpec, AgentRunner

    tools = ToolRegistry()
    shared_events: list[str] = []
    read_a = _DelayTool("read_a", delay=0.03, read_only=True, shared_events=shared_events)
    read_b = _DelayTool("read_b", delay=0.03, read_only=True, shared_events=shared_events)
    ddg_like = _DelayTool(
        "ddg_like",
        delay=0.01,
        read_only=True,
        shared_events=shared_events,
        exclusive=True,
    )
    tools.register(read_a)
    tools.register(ddg_like)
    tools.register(read_b)

    runner = AgentRunner(MagicMock())
    await runner._execute_tools(
        AgentRunSpec(
            initial_messages=[],
            tools=tools,
            model="test-model",
            max_iterations=1,
            max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
            concurrent_tools=True,
        ),
        [
            ToolCallRequest(id="ro1", name="read_a", arguments={}),
            ToolCallRequest(id="ddg1", name="ddg_like", arguments={}),
            ToolCallRequest(id="ro2", name="read_b", arguments={}),
        ],
        *_empty_tool_tracking(),
    )

    assert shared_events[0] == "start:read_a"
    assert shared_events.index("end:read_a") < shared_events.index("start:ddg_like")
    assert shared_events.index("end:ddg_like") < shared_events.index("start:read_b")


@pytest.mark.asyncio
async def test_runner_blocks_repeated_external_fetches():
    from nanobot.agent.runner import AgentRunSpec, AgentRunner

    provider = MagicMock()
    captured_final_call: list[dict] = []
    call_count = {"n": 0}

    async def chat_with_retry(*, messages, **kwargs):
        call_count["n"] += 1
        if call_count["n"] <= 3:
            return LLMResponse(
                content="working",
                tool_calls=[ToolCallRequest(id=f"call_{call_count['n']}", name="web_fetch", arguments={"url": "https://example.com"})],
                usage={},
            )
        captured_final_call[:] = messages
        return LLMResponse(content="done", tool_calls=[], usage={})

    provider.chat_with_retry = chat_with_retry
    tools = MagicMock()
    tools.get_definitions.return_value = []
    tools.execute = AsyncMock(return_value="page content")

    runner = AgentRunner(provider)
    result = await runner.run(AgentRunSpec(
        initial_messages=[{"role": "user", "content": "research task"}],
        tools=tools,
        model="test-model",
        max_iterations=4,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
    ))

    # The batch guard fires on the 3rd identical single-tool batch, injecting a
    # forcing message before the per-tool external-lookup guard can turn it into
    # a fatal error.  The model then produces a final answer ("done").
    assert result.final_content is not None
    assert tools.execute.await_count == 2
    assert result.had_injections


@pytest.mark.asyncio
async def test_runner_injects_on_repeated_tool_batch():
    from nanobot.agent.runner import AgentRunSpec, AgentRunner
    from nanobot.utils.runtime import REPEATED_TOOL_BATCH_PROMPT

    same_batch = [
        ToolCallRequest(id="s1", name="web_search", arguments={"query": "tallinn events"}),
        ToolCallRequest(id="s2", name="web_search", arguments={"query": "tartu events"}),
    ]
    provider = MagicMock()
    call_count = {"n": 0}
    captured_messages: list[list[dict]] = []

    async def chat_with_retry(*, messages, **kwargs):
        call_count["n"] += 1
        if call_count["n"] <= 3:
            return LLMResponse(content="", tool_calls=list(same_batch), usage={})
        captured_messages.append(messages)
        return LLMResponse(content="here is the answer", tool_calls=[], usage={})

    provider.chat_with_retry = chat_with_retry
    tools = MagicMock()
    tools.get_definitions.return_value = []
    tools.execute = AsyncMock(return_value="search results")

    runner = AgentRunner(provider)
    result = await runner.run(AgentRunSpec(
        initial_messages=[{"role": "user", "content": "find events"}],
        tools=tools,
        model="test-model",
        max_iterations=6,
        max_tool_result_chars=_MAX_TOOL_RESULT_CHARS,
    ))

    assert result.final_content == "here is the answer"
    assert tools.execute.await_count == 4  # two real batches × two tools; third blocked
    final_msgs = captured_messages[-1]
    roles = [m["role"] for m in final_msgs]
    # Forcing message must appear in history.
    assert any(
        m.get("role") == "user" and REPEATED_TOOL_BATCH_PROMPT in m.get("content", "")
        for m in final_msgs
    )
    # The blocked assistant turn (tool_calls) must precede the forcing message so it
    # is contextually coherent for the model.
    forcing_idx = next(
        i for i, m in enumerate(final_msgs)
        if m.get("role") == "user" and REPEATED_TOOL_BATCH_PROMPT in m.get("content", "")
    )
    assert any(
        final_msgs[i].get("role") == "assistant" and final_msgs[i].get("tool_calls")
        for i in range(forcing_idx)
    )
