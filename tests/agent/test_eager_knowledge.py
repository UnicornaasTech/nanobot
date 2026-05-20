"""Tests for eager knowledge promotion into history.jsonl."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from nanobot.agent.eager_knowledge import (
    EagerKnowledgeManager,
    enrich_messages_for_archive,
    provenance_prefix,
    read_eager_cursor,
    slack_provenance_from_inbound,
)
from nanobot.agent.memory import Consolidator, MemoryStore
from nanobot.bus.events import InboundMessage
from nanobot.config.schema import EagerKnowledgeConfig
from nanobot.session.manager import Session, SessionManager


def _manager(
    tmp_path: Path,
    *,
    consolidator: Consolidator | None = None,
    config: EagerKnowledgeConfig | None = None,
) -> tuple[EagerKnowledgeManager, SessionManager, Consolidator]:
    sessions = SessionManager(tmp_path)
    store = MemoryStore(tmp_path)
    if consolidator is None:
        provider = MagicMock()
        consolidator = Consolidator(
            store=store,
            provider=provider,
            model="test-model",
            sessions=sessions,
            context_window_tokens=8192,
            build_messages=MagicMock(return_value=[]),
            get_tool_definitions=MagicMock(return_value=[]),
        )
    scheduled: list[asyncio.Task] = []

    def schedule_background(coro):
        scheduled.append(asyncio.create_task(coro))

    mgr = EagerKnowledgeManager(
        sessions=sessions,
        consolidator=consolidator,
        config=config
        or EagerKnowledgeConfig(enabled=True, min_batch=3, singleton_idle_s=0, max_batch=20),
        schedule_background=schedule_background,
    )
    mgr._scheduled = scheduled  # type: ignore[attr-defined]
    return mgr, sessions, consolidator


@pytest.mark.asyncio
async def test_singleton_flushes_to_history_after_idle(tmp_path: Path) -> None:
    mgr, sessions, _ = _manager(tmp_path)
    session = sessions.get_or_create("slack:C1")
    session.add_message("user", "ambient one-off")
    sessions.save(session)

    assert await mgr.maybe_flush("slack:C1", reason="scheduled")

    history = (tmp_path / "memory" / "history.jsonl").read_text(encoding="utf-8")
    assert "[EAGER singleton slack:C1]" in history
    assert "ambient one-off" in history
    assert session.metadata.get("_prospr_eager_cursor") == 1


@pytest.mark.asyncio
async def test_batch_triggers_archive_and_advances_cursor(tmp_path: Path) -> None:
    mgr, sessions, consolidator = _manager(tmp_path)
    consolidator.archive = AsyncMock(return_value="summary chunk")  # type: ignore[method-assign]

    session = sessions.get_or_create("slack:C2")
    for i in range(3):
        session.add_message("user", f"line {i}")
    sessions.save(session)

    assert await mgr.maybe_flush("slack:C2", reason="scheduled")

    consolidator.archive.assert_awaited_once()
    archived = consolidator.archive.await_args.args[0]
    assert len(archived) == 3
    assert session.metadata.get("_prospr_eager_cursor") == 3


@pytest.mark.asyncio
async def test_no_duplicate_when_cursor_caught_up(tmp_path: Path) -> None:
    mgr, sessions, consolidator = _manager(tmp_path)
    consolidator.archive = AsyncMock(return_value="summary")  # type: ignore[method-assign]

    session = sessions.get_or_create("slack:C3")
    session.add_message("user", "only one")
    sessions.save(session)
    await mgr.maybe_flush("slack:C3", reason="scheduled")
    consolidator.archive.reset_mock()

    assert not await mgr.maybe_flush("slack:C3", reason="scheduled")
    consolidator.archive.assert_not_called()


def test_slack_provenance_root_and_reply() -> None:
    root = InboundMessage(
        channel="slack",
        sender_id="u1",
        chat_id="C9",
        content="top-level",
        metadata={
            "slack": {
                "event": {"ts": "1716.01", "channel": "C9"},
            },
        },
    )
    root_fields = slack_provenance_from_inbound(root)
    assert root_fields["slack_reply_kind"] == "root"
    assert root_fields["slack_root_ts"] == "1716.01"
    assert root_fields["slack_ts"] == "1716.01"

    reply = InboundMessage(
        channel="slack",
        sender_id="u1",
        chat_id="C9",
        content="thread reply",
        metadata={
            "slack": {
                "event": {
                    "ts": "1716.42",
                    "thread_ts": "1716.01",
                    "channel": "C9",
                },
            },
        },
    )
    reply_fields = slack_provenance_from_inbound(reply)
    assert reply_fields["slack_reply_kind"] == "reply"
    assert reply_fields["slack_root_ts"] == "1716.01"
    assert reply_fields["slack_ts"] == "1716.42"

    root_msg = {"source_chat_id": "C9", "slack_reply_kind": "root", "slack_ts": "1716.01"}
    reply_msg = {
        "source_chat_id": "C9",
        "slack_reply_kind": "reply",
        "slack_root_ts": "1716.01",
        "slack_ts": "1716.42",
        "content": "follow-up",
    }
    enriched = enrich_messages_for_archive(
        [
            {**root_msg, "content": "top"},
            {**reply_msg, "content": "follow-up"},
        ]
    )
    assert "root ts=1716.01" in enriched[0]["content"]
    assert "reply root=1716.01" in enriched[1]["content"]
    assert provenance_prefix(root_msg).startswith("[slack C9 root")


@pytest.mark.asyncio
async def test_linked_archive_lines_share_root_ts(tmp_path: Path) -> None:
    mgr, sessions, consolidator = _manager(
        tmp_path,
        config=EagerKnowledgeConfig(enabled=True, min_batch=2, singleton_idle_s=0, max_batch=20),
    )
    consolidator.archive = AsyncMock(return_value="linked")  # type: ignore[method-assign]

    session = sessions.get_or_create("slack:C-thread")
    session.add_message(
        "user",
        "root post",
        source_chat_id="C-thread",
        slack_reply_kind="root",
        slack_ts="1716.01",
        slack_root_ts="1716.01",
    )
    session.add_message(
        "user",
        "reply post",
        source_chat_id="C-thread",
        slack_reply_kind="reply",
        slack_ts="1716.42",
        slack_root_ts="1716.01",
    )
    sessions.save(session)

    await mgr.maybe_flush("slack:C-thread", reason="scheduled")
    archived = consolidator.archive.await_args.args[0]
    assert any("root ts=1716.01" in m["content"] for m in archived)
    assert any("reply root=1716.01" in m["content"] for m in archived)


@pytest.mark.asyncio
async def test_token_consolidation_skips_eager_archived_prefix(tmp_path: Path) -> None:
    """Overflow consolidation must not re-archive messages eager already promoted."""
    sessions = SessionManager(tmp_path)
    store = MemoryStore(tmp_path)
    provider = MagicMock()
    provider.generation = MagicMock(max_tokens=1024)
    consolidator = Consolidator(
        store=store,
        provider=provider,
        model="test-model",
        sessions=sessions,
        context_window_tokens=8192,
        build_messages=MagicMock(return_value=[]),
        get_tool_definitions=MagicMock(return_value=[]),
    )
    consolidator.archive = AsyncMock(return_value="overflow summary")  # type: ignore[method-assign]

    session = sessions.get_or_create("slack:C-dedupe")
    for i in range(4):
        session.add_message("user", f"msg {i}")
    session.metadata["_prospr_eager_cursor"] = 3
    session.last_consolidated = 0
    sessions.save(session)

    boundary = consolidator.pick_consolidation_boundary(session, tokens_to_remove=1)
    assert boundary is not None
    end_idx = boundary[0]
    assert end_idx > 3

    from nanobot.agent.eager_knowledge import eager_consolidation_start

    start_idx = eager_consolidation_start(session)
    assert start_idx == 3
    chunk = session.messages[start_idx:end_idx]
    assert len(chunk) == end_idx - 3
    await consolidator.archive(chunk)
    consolidator.archive.assert_awaited_once()
    archived = consolidator.archive.await_args.args[0]
    assert len(archived) == 1
    assert archived[0]["content"] == "msg 3"


def test_eager_cursor_shifts_when_session_prefix_trimmed(tmp_path: Path) -> None:
    session = Session(key="slack:C-trim")
    for i in range(10):
        session.add_message("user", f"m{i}")
    session.metadata["_prospr_eager_cursor"] = 7
    session.retain_recent_legal_suffix(5)
    assert len(session.messages) == 5
    assert read_eager_cursor(session) == 2
