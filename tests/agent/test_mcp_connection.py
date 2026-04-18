"""Tests for MCP connection lifecycle in AgentLoop."""

from __future__ import annotations

from contextlib import AsyncExitStack
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nanobot.agent.loop import AgentLoop
from nanobot.agent.tools.mcp import MCPToolWrapper
from nanobot.bus.queue import MessageBus


def _make_loop(tmp_path, *, mcp_servers: dict | None = None) -> AgentLoop:
    bus = MessageBus()
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    provider.generation.max_tokens = 4096
    return AgentLoop(
        bus=bus,
        provider=provider,
        workspace=tmp_path,
        model="test-model",
        mcp_servers=mcp_servers or {"test": object()},
    )


@pytest.mark.asyncio
async def test_connect_mcp_retries_when_no_servers_connect(tmp_path, monkeypatch: pytest.MonkeyPatch):
    loop = _make_loop(tmp_path)
    attempts = 0

    async def _fake_connect(_servers, _registry, **_kwargs):
        nonlocal attempts
        attempts += 1
        return {}

    monkeypatch.setattr("nanobot.agent.tools.mcp.connect_mcp_servers", _fake_connect)

    await loop._connect_mcp()
    await loop._connect_mcp()

    assert attempts == 2
    assert loop._mcp_connected is False
    assert loop._mcp_stacks == {}


@pytest.mark.asyncio
async def test_reset_mcp_transport_after_failure_clears_registry(tmp_path) -> None:
    loop = _make_loop(tmp_path, mcp_servers={"srv": object()})
    tool_def = SimpleNamespace(
        name="t",
        description="",
        inputSchema={"type": "object", "properties": {}},
    )
    wrapper = MCPToolWrapper(MagicMock(), "srv", tool_def)
    loop.tools.register(wrapper)
    stack = AsyncExitStack()
    await stack.__aenter__()
    loop._mcp_stacks["srv"] = stack
    loop._mcp_connected = True

    await loop._reset_mcp_transport_after_failure("bear")

    assert "mcp_srv_t" not in loop.tools.tool_names
    assert loop._mcp_stacks == {}
    assert loop._mcp_connected is False
