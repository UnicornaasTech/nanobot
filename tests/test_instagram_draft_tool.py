"""Tests for create_instagram_draft tool and review state helper."""

from __future__ import annotations

import json
import time

import pytest

from nanobot.agent.tools.context import RequestContext
from nanobot.agent.tools.instagram_draft import CreateInstagramDraftTool
from nanobot.channels.instagram import review_state as state
from nanobot.channels.instagram.review_state import compose_chat_id


@pytest.fixture(autouse=True)
def _clear_state(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    state._pending_drafts.clear()
    monkeypatch.setattr(state, "_thread_map_path", lambda: tmp_path / "threads.json")


@pytest.mark.asyncio
async def test_create_instagram_draft_rejects_non_instagram_channel() -> None:
    tool = CreateInstagramDraftTool()
    tool.set_context(RequestContext(channel="email", chat_id="alice@example.com"))
    result = await tool.execute(body="Hello")
    assert result.startswith("Error:")
    assert "instagram" in result.lower()


@pytest.mark.asyncio
async def test_create_instagram_draft_stores_payload() -> None:
    tool = CreateInstagramDraftTool()
    tool.set_context(RequestContext(channel="instagram", chat_id="IG123"))
    result = await tool.execute(body="Thanks for reaching out!", review_notes="Check policy")
    payload = json.loads(result)
    assert payload["status"] == "instagram_draft_queued_not_sent"
    assert payload["chat_id"] == "IG123"

    stored = state.peek_draft("IG123")
    assert stored is not None
    assert stored.draft_text == "Thanks for reaching out!"
    assert stored.review_notes == "Check policy"


@pytest.mark.asyncio
async def test_create_instagram_draft_rejects_empty_body() -> None:
    tool = CreateInstagramDraftTool()
    tool.set_context(RequestContext(channel="instagram", chat_id="IG123"))
    result = await tool.execute(body="   ")
    assert result.startswith("Error:")


def test_consume_draft_removes_entry() -> None:
    state.set_draft("IG1", "draft one")
    consumed = state.consume_draft("IG1")
    assert consumed is not None
    assert consumed.draft_text == "draft one"
    assert state.peek_draft("IG1") is None


def test_draft_ttl_expiration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(state, "_DRAFT_TTL_SECONDS", 1)
    state.set_draft("IG2", "old draft")
    state._pending_drafts["IG2"].created_at = time.time() - 2
    assert state.consume_draft("IG2") is None


def test_draft_stored_under_namespaced_chat_id() -> None:
    chat_id = compose_chat_id("brand_a", "IG123")
    state.set_draft(chat_id, "namespaced draft")
    stored = state.peek_draft(chat_id)
    assert stored is not None
    assert stored.draft_text == "namespaced draft"
    assert state.peek_draft("IG123") is None


def test_slack_thread_mapping_persists(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "threads.json"
    monkeypatch.setattr(state, "_thread_map_path", lambda: path)
    state.set_slack_thread_ts("IG9", "111.222")
    assert state.get_slack_thread_ts("IG9") == "111.222"
    assert json.loads(path.read_text(encoding="utf-8")) == {"IG9": "111.222"}
    state.clear_slack_thread_ts("IG9")
    assert state.get_slack_thread_ts("IG9") is None
