"""CreateGmailDraftTool request-context wiring (no live Gmail)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from nanobot.agent.tools.context import RequestContext
from nanobot.agent.tools.gmail_auth import GmailDraftToolConfig
from nanobot.agent.tools.gmail_draft import CreateGmailDraftTool


def _configured_tool() -> CreateGmailDraftTool:
    return CreateGmailDraftTool(
        gmail_draft_config=GmailDraftToolConfig(
            client_id="id",
            client_secret="secret",
            refresh_token="refresh",
        )
    )


@pytest.mark.asyncio
async def test_tool_passes_in_reply_to_from_email_context(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_create(**kwargs):
        captured.update(kwargs)
        return {
            "draft_id": "d1",
            "thread_id": "th1",
            "gmail_url": "https://mail.google.com/mail/u/0/#inbox/th1",
            "status": "draft_created_not_sent",
            "reply_in_thread": True,
            "in_reply_to": "<orig@example.com>",
        }

    monkeypatch.setattr("nanobot.agent.tools.gmail_draft.create_gmail_draft", fake_create)

    tool = _configured_tool()
    tool.set_context(
        RequestContext(
            channel="email",
            chat_id="cust@example.com",
            message_id="<orig@example.com>",
            metadata={
                "message_id": "<orig@example.com>",
                "subject": "Help",
                "date": "Sat, 23 May 2026 12:00:00 +0000",
                "sender_email": "cust@example.com",
                "email_body": "Please assist.",
            },
        )
    )

    out = await tool.execute(to="cust@example.com", subject="Help", body="Sure.")

    assert "draft_id" not in out.lower()
    assert "Open in Gmail:" in out
    assert "original email thread" in out
    assert captured["in_reply_to"] == "<orig@example.com>"
    assert captured["original_body"] == "Please assist."
    assert captured["original_from"] == "cust@example.com"


@pytest.mark.asyncio
async def test_tool_non_email_channel_has_no_in_reply_to(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict = {}

    def fake_create(**kwargs):
        captured.update(kwargs)
        return {
            "draft_id": "d2",
            "status": "draft_created_not_sent",
            "reply_in_thread": False,
        }

    monkeypatch.setattr("nanobot.agent.tools.gmail_draft.create_gmail_draft", fake_create)

    tool = _configured_tool()
    tool.set_context(RequestContext(channel="cli", chat_id="local"))

    await tool.execute(to="a@b.com", subject="Hi", body="Body")

    assert captured.get("in_reply_to") is None
