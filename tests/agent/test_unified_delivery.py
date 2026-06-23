"""Tests for unified-session delivery-target injection guard."""

import asyncio
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from nanobot.agent.loop import UNIFIED_SESSION_KEY, AgentLoop
from nanobot.agent.unified_delivery import (
    DeliveryTarget,
    allows_unified_mid_turn_injection,
    delivery_target_from_message,
)
from nanobot.bus.events import InboundMessage, OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.providers.base import LLMResponse


def _make_loop(tmp_path: Path, unified_session: bool = True) -> AgentLoop:
    bus = MessageBus()
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    with patch("nanobot.agent.loop.SessionManager"), \
         patch("nanobot.agent.loop.SubagentManager") as mock_sub_mgr:
        mock_sub_mgr.return_value.cancel_by_session = AsyncMock(return_value=0)
        loop = AgentLoop(
            bus=bus,
            provider=provider,
            workspace=tmp_path,
            unified_session=unified_session,
        )
    loop.tools.get_definitions = MagicMock(return_value=[])
    return loop


class TestDeliveryTargetHelpers:
    def test_slack_thread_ts_in_target(self) -> None:
        msg = InboundMessage(
            channel="slack",
            sender_id="u",
            chat_id="C1",
            content="hi",
            metadata={"slack": {"thread_ts": "111.222"}},
        )
        assert delivery_target_from_message(msg) == DeliveryTarget(
            "slack", "C1", "111.222"
        )

    def test_allows_injection_same_surface_unified(self) -> None:
        origin = DeliveryTarget("slack", "D1")
        inbound = InboundMessage(channel="slack", sender_id="u", chat_id="D1", content="x")
        assert allows_unified_mid_turn_injection(
            unified_session=True,
            session_key=UNIFIED_SESSION_KEY,
            inbound=inbound,
            active_origin=origin,
        )

    def test_blocks_injection_cross_channel_unified(self) -> None:
        origin = DeliveryTarget("slack", "D1")
        inbound = InboundMessage(channel="telegram", sender_id="u", chat_id="T1", content="x")
        assert not allows_unified_mid_turn_injection(
            unified_session=True,
            session_key=UNIFIED_SESSION_KEY,
            inbound=inbound,
            active_origin=origin,
        )

    def test_blocks_injection_different_slack_thread(self) -> None:
        origin = DeliveryTarget("slack", "C1", "111.222")
        inbound = InboundMessage(
            channel="slack",
            sender_id="u",
            chat_id="C1",
            content="x",
            metadata={"slack": {"thread_ts": "333.444"}},
        )
        assert not allows_unified_mid_turn_injection(
            unified_session=True,
            session_key=UNIFIED_SESSION_KEY,
            inbound=inbound,
            active_origin=origin,
        )

    def test_non_unified_session_always_allows(self) -> None:
        origin = DeliveryTarget("slack", "D1")
        inbound = InboundMessage(channel="telegram", sender_id="u", chat_id="T1", content="x")
        assert allows_unified_mid_turn_injection(
            unified_session=False,
            session_key="slack:D1",
            inbound=inbound,
            active_origin=origin,
        )


@pytest.mark.asyncio
async def test_cross_channel_followup_not_injected_while_turn_active(tmp_path: Path) -> None:
    """Cross-surface messages wait for the lock instead of mid-turn injection."""
    loop = _make_loop(tmp_path, unified_session=True)
    loop._dispatch = AsyncMock()  # type: ignore[method-assign]

    pending = asyncio.Queue(maxsize=20)
    loop._pending_queues[UNIFIED_SESSION_KEY] = pending
    loop._pending_delivery_origins[UNIFIED_SESSION_KEY] = DeliveryTarget("slack", "D1")

    run_task = asyncio.create_task(loop.run())
    follow_up = InboundMessage(
        channel="telegram", sender_id="u", chat_id="T1", content="from telegram"
    )
    await loop.bus.publish_inbound(follow_up)

    deadline = time.time() + 2
    while loop._dispatch.await_count == 0 and time.time() < deadline:
        await asyncio.sleep(0.01)

    loop.stop()
    await asyncio.wait_for(run_task, timeout=2)

    assert loop._dispatch.await_count == 1
    assert pending.empty()


@pytest.mark.asyncio
async def test_same_channel_followup_still_injected(tmp_path: Path) -> None:
    """Same delivery surface still uses the pending queue in unified mode."""
    loop = _make_loop(tmp_path, unified_session=True)
    loop._dispatch = AsyncMock()  # type: ignore[method-assign]

    pending = asyncio.Queue(maxsize=20)
    loop._pending_queues[UNIFIED_SESSION_KEY] = pending
    loop._pending_delivery_origins[UNIFIED_SESSION_KEY] = DeliveryTarget("slack", "D1")

    run_task = asyncio.create_task(loop.run())
    follow_up = InboundMessage(channel="slack", sender_id="u", chat_id="D1", content="follow-up")
    await loop.bus.publish_inbound(follow_up)

    deadline = time.time() + 2
    while pending.empty() and time.time() < deadline:
        await asyncio.sleep(0.01)

    loop.stop()
    await asyncio.wait_for(run_task, timeout=2)

    assert loop._dispatch.await_count == 0
    assert pending.get_nowait().content == "follow-up"


@pytest.mark.asyncio
async def test_cross_channel_turn_replies_to_correct_surface(tmp_path: Path) -> None:
    """After the active turn ends, the deferred message replies to its channel."""
    loop = _make_loop(tmp_path, unified_session=True)
    loop.provider.chat_with_retry = AsyncMock(
        return_value=LLMResponse(content="slack answer", tool_calls=[], usage={})
    )

    slack_turn_started = asyncio.Event()
    release_slack = asyncio.Event()

    original_dispatch = loop._dispatch

    async def gated_dispatch(msg: InboundMessage) -> None:
        if msg.channel == "slack":
            slack_turn_started.set()
            await release_slack.wait()
        await original_dispatch(msg)

    loop._dispatch = gated_dispatch  # type: ignore[method-assign]

    run_task = asyncio.create_task(loop.run())
    await loop.bus.publish_inbound(
        InboundMessage(channel="slack", sender_id="u", chat_id="D1", content="slack q")
    )
    await asyncio.wait_for(slack_turn_started.wait(), timeout=2)

    await loop.bus.publish_inbound(
        InboundMessage(channel="telegram", sender_id="u", chat_id="T1", content="telegram q")
    )
    await asyncio.sleep(0.05)
    release_slack.set()

    outbounds: list[OutboundMessage] = []
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            outbounds.append(await asyncio.wait_for(loop.bus.consume_outbound(), timeout=0.2))
        except asyncio.TimeoutError:
            if len(outbounds) >= 2:
                break

    loop.stop()
    await asyncio.wait_for(run_task, timeout=3)

    replies = [m for m in outbounds if m.content and not m.metadata.get("_turn_end")]
    channels = {m.channel for m in replies}
    assert "slack" in channels
    assert "telegram" in channels
    telegram_replies = [m for m in replies if m.channel == "telegram"]
    assert any("slack answer" in m.content or "telegram" in m.content.lower() for m in telegram_replies) or any(
        m.chat_id == "T1" for m in telegram_replies
    )
