"""Email draft policy and Gmail draft tool (no live Gmail)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from nanobot.bus.events import OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.channels.email import EmailChannel, EmailConfig


def test_send_message_is_disabled() -> None:
    ch = EmailChannel.__new__(EmailChannel)
    with pytest.raises(NotImplementedError, match="create_gmail_draft"):
        ch.send_message("a@b.com", "Test", "Body")


@pytest.mark.asyncio
async def test_send_is_disabled() -> None:
    bus = MessageBus()
    cfg = EmailConfig(
        consent_granted=True,
        imap_host="imap.example.com",
        imap_username="u",
        imap_password="p",
    )
    ch = EmailChannel(cfg, bus)
    msg = OutboundMessage(channel="email", chat_id="x@y.com", content="hi")
    with pytest.raises(NotImplementedError, match="create_gmail_draft"):
        await ch.send(msg)


def test_imap_only_validate_config() -> None:
    bus = MessageBus()
    cfg = EmailConfig(
        consent_granted=True,
        imap_host="imap.example.com",
        imap_username="u",
        imap_password="p",
    )
    ch = EmailChannel(cfg, bus)
    assert ch._validate_config() is True

    cfg2 = EmailConfig(consent_granted=True, imap_host="", imap_username="u", imap_password="p")
    ch2 = EmailChannel(cfg2, bus)
    assert ch2._validate_config() is False


def test_draft_creates_not_sends(monkeypatch: pytest.MonkeyPatch) -> None:
    from nanobot.agent.tools import gmail_draft as gd

    mock_service = MagicMock()
    exec_result = {
        "id": "draft123",
        "message": {"threadId": "th1"},
    }
    mock_service.users.return_value.drafts.return_value.create.return_value.execute.return_value = (
        exec_result
    )

    monkeypatch.setattr(
        "nanobot.agent.tools.gmail_auth.get_gmail_service",
        lambda: mock_service,
    )

    result = gd.create_gmail_draft(
        to="a@b.com",
        subject="Hi",
        body="Body",
        thread_id="th1",
    )
    assert result["status"] == "draft_created_not_sent"
    assert result["draft_id"] == "draft123"

    drafts_create = mock_service.users.return_value.drafts.return_value.create
    assert drafts_create.call_count == 1
    _args, kwargs = drafts_create.call_args
    assert kwargs["userId"] == "me"
    assert kwargs["body"]["message"]["threadId"] == "th1"
    assert "raw" in kwargs["body"]["message"]


def test_email_module_has_no_smtplib_runtime_import() -> None:
    from pathlib import Path

    import nanobot.channels.email as mod

    src = Path(mod.__file__).read_text(encoding="utf-8")
    assert "import smtplib" not in src
    assert "smtplib." not in src


def test_poll_interval_clamped_to_sixty_seconds() -> None:
    assert EmailChannel._clamp_poll_interval(30) == 30
    assert EmailChannel._clamp_poll_interval(60) == 60
    assert EmailChannel._clamp_poll_interval(120) == 60
    assert EmailChannel._clamp_poll_interval(3) == 5


def test_default_poll_interval_is_sixty() -> None:
    assert EmailConfig().poll_interval_seconds == 60
    assert EmailConfig().imap_idle_enabled is True
