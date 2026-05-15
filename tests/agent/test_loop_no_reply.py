"""Tests for InboundMessage.no_reply silent session append in AgentLoop._dispatch."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from nanobot.agent.loop import AgentLoop
from nanobot.bus.events import InboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.providers.base import LLMResponse


def _make_loop(tmp_path: Path) -> AgentLoop:
    bus = MessageBus()
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    provider.chat_with_retry = AsyncMock(
        return_value=LLMResponse(content="should-not-run", tool_calls=[])
    )
    loop = AgentLoop(bus=bus, provider=provider, workspace=tmp_path, model="test-model")
    loop.tools.get_definitions = MagicMock(return_value=[])
    loop.consolidator.maybe_consolidate_by_tokens = AsyncMock(return_value=False)  # type: ignore[method-assign]
    return loop


@pytest.mark.asyncio
async def test_no_reply_silent_append_no_llm_no_outbound(tmp_path: Path) -> None:
    loop = _make_loop(tmp_path)
    msg = InboundMessage(
        channel="slack",
        sender_id="u1",
        chat_id="C123",
        content="ambient channel line",
        no_reply=True,
    )
    await loop._dispatch(msg)

    loop.provider.chat_with_retry.assert_not_called()

    session = loop.sessions.get_or_create("slack:C123")
    assert len(session.messages) == 1
    assert session.messages[0]["role"] == "user"
    assert session.messages[0]["content"] == "ambient channel line"
    assert session.metadata.get("pending_user_turn") is None

    assert loop.bus.outbound_size == 0


@pytest.mark.asyncio
async def test_no_reply_silent_even_with_prior_assistant(tmp_path: Path) -> None:
    loop = _make_loop(tmp_path)
    session = loop.sessions.get_or_create("slack:C99")
    session.add_message("assistant", "prior reply from elsewhere")
    loop.sessions.save(session)

    msg = InboundMessage(
        channel="slack",
        sender_id="u1",
        chat_id="C99",
        content="another ambient line",
        no_reply=True,
    )
    await loop._dispatch(msg)

    loop.provider.chat_with_retry.assert_not_called()
    session = loop.sessions.get_or_create("slack:C99")
    assert len(session.messages) == 2
    assert session.messages[-1]["role"] == "user"
    assert session.messages[-1]["content"] == "another ambient line"
    assert loop.bus.outbound_size == 0


@pytest.mark.asyncio
async def test_no_reply_bypassed_for_dispatchable_command(tmp_path: Path) -> None:
    loop = _make_loop(tmp_path)
    msg = InboundMessage(
        channel="slack",
        sender_id="u1",
        chat_id="C555",
        content="/help",
        no_reply=True,
    )
    await loop._dispatch(msg)

    session = loop.sessions.get_or_create("slack:C555")
    assert any(m.get("_command") for m in session.messages)
    assert loop.bus.outbound_size > 0
    while loop.bus.outbound_size > 0:
        await loop.bus.consume_outbound()


@pytest.mark.asyncio
async def test_append_no_reply_waits_for_session_lock(tmp_path: Path) -> None:
    """no_reply background persist must not race ahead of an in-flight session lock."""
    loop = _make_loop(tmp_path)
    key = "slack:C-lock"
    lock = asyncio.Lock()
    loop._session_locks[key] = lock
    started = asyncio.Event()

    async def holder() -> None:
        async with lock:
            started.set()
            await asyncio.sleep(0.08)

    h = asyncio.create_task(holder())
    await started.wait()

    msg = InboundMessage(
        channel="slack",
        sender_id="u1",
        chat_id="C-lock",
        content="during busy session",
        no_reply=True,
    )
    append_task = asyncio.create_task(
        loop._append_no_reply_when_session_unlocked(msg)
    )
    await asyncio.sleep(0.02)
    assert len(loop.sessions.get_or_create(key).messages) == 0

    await h
    await append_task

    sess = loop.sessions.get_or_create(key)
    assert len(sess.messages) == 1
    assert sess.messages[0]["content"] == "during busy session"
