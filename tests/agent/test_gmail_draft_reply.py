"""Gmail draft reply threading and quoting (no live Gmail)."""

from __future__ import annotations

import base64
from email import message_from_bytes
from unittest.mock import MagicMock

import pytest

from nanobot.agent.tools import gmail_draft as gd
from nanobot.agent.tools.gmail_auth import GmailDraftToolConfig


def _configured() -> GmailDraftToolConfig:
    return GmailDraftToolConfig(
        client_id="id",
        client_secret="secret",
        refresh_token="refresh",
    )


def _gmail_message(
    *,
    thread_id: str = "thread-abc",
    message_id: str = "<orig@example.com>",
    subject: str = "Help request",
    from_addr: str = "Customer <cust@example.com>",
    date: str = "Sat, 23 May 2026 12:00:00 +0000",
    body: str = "I need assistance.",
) -> dict:
    encoded = base64.urlsafe_b64encode(body.encode()).decode().rstrip("=")
    return {
        "id": "gmail-msg-1",
        "threadId": thread_id,
        "payload": {
            "headers": [
                {"name": "Message-ID", "value": message_id},
                {"name": "Subject", "value": subject},
                {"name": "From", "value": from_addr},
                {"name": "Date", "value": date},
            ],
            "mimeType": "text/plain",
            "body": {"data": encoded},
        },
    }


def _decode_raw(raw: str) -> message_from_bytes:
    padded = raw + "=" * (-len(raw) % 4)
    return message_from_bytes(base64.urlsafe_b64decode(padded.encode()))


def test_reply_draft_threads_and_quotes(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_service = MagicMock()
    mock_service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
        "messages": [{"id": "gmail-msg-1"}]
    }
    mock_service.users.return_value.messages.return_value.get.return_value.execute.return_value = (
        _gmail_message()
    )
    mock_service.users.return_value.drafts.return_value.create.return_value.execute.return_value = {
        "id": "draft456",
        "message": {"threadId": "thread-abc"},
    }

    monkeypatch.setattr(
        "nanobot.agent.tools.gmail_auth.get_gmail_service",
        lambda _cfg: mock_service,
    )

    result = gd.create_gmail_draft(
        to="cust@example.com",
        subject="Help request",
        body="Thanks for reaching out.",
        in_reply_to="<orig@example.com>",
        gmail_draft_config=_configured(),
    )

    assert result["reply_in_thread"] is True
    assert result["thread_id"] == "thread-abc"
    assert "inbox/thread-abc" in result["gmail_url"]

    drafts_create = mock_service.users.return_value.drafts.return_value.create
    _args, kwargs = drafts_create.call_args
    assert kwargs["body"]["message"]["threadId"] == "thread-abc"
    parsed = _decode_raw(kwargs["body"]["message"]["raw"])
    assert parsed["In-Reply-To"] == "<orig@example.com>"
    assert "<orig@example.com>" in parsed["References"]
    assert parsed["Subject"] == "Re: Help request"
    text = parsed.get_payload(decode=True).decode()
    assert "Thanks for reaching out." in text
    assert "Customer <cust@example.com> wrote:" in text
    assert "> I need assistance." in text


def test_reply_subject_keeps_re_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_service = MagicMock()
    mock_service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
        "messages": [{"id": "gmail-msg-1"}]
    }
    mock_service.users.return_value.messages.return_value.get.return_value.execute.return_value = (
        _gmail_message(subject="Re: Help request")
    )
    mock_service.users.return_value.drafts.return_value.create.return_value.execute.return_value = {
        "id": "d1",
        "message": {"threadId": "thread-abc"},
    }
    monkeypatch.setattr(
        "nanobot.agent.tools.gmail_auth.get_gmail_service",
        lambda _cfg: mock_service,
    )

    gd.create_gmail_draft(
        to="cust@example.com",
        subject="Re: Help request",
        body="Follow-up",
        in_reply_to="<orig@example.com>",
        gmail_draft_config=_configured(),
    )
    parsed = _decode_raw(
        mock_service.users.return_value.drafts.return_value.create.call_args.kwargs["body"]["message"]["raw"]
    )
    assert parsed["Subject"] == "Re: Help request"


def test_fallback_quote_without_gmail_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_service = MagicMock()
    mock_service.users.return_value.messages.return_value.list.return_value.execute.return_value = {
        "messages": []
    }
    mock_service.users.return_value.drafts.return_value.create.return_value.execute.return_value = {
        "id": "draft789",
        "message": {"threadId": "thread-fallback"},
    }
    monkeypatch.setattr(
        "nanobot.agent.tools.gmail_auth.get_gmail_service",
        lambda _cfg: mock_service,
    )

    result = gd.create_gmail_draft(
        to="cust@example.com",
        subject="Question",
        body="Reply text",
        in_reply_to="orig@example.com",
        thread_id="thread-fallback",
        original_from="cust@example.com",
        original_date="Sat, 23 May 2026 12:00:00 +0000",
        original_body="Original line",
        gmail_draft_config=_configured(),
    )

    assert result["thread_id"] == "thread-fallback"
    parsed = _decode_raw(
        mock_service.users.return_value.drafts.return_value.create.call_args.kwargs["body"]["message"]["raw"]
    )
    assert parsed["In-Reply-To"] == "<orig@example.com>"
    assert "> Original line" in parsed.get_payload(decode=True).decode()


def test_quote_original_lines() -> None:
    assert gd._quote_original_lines("a\n\nb") == "> a\n>\n> b"


def test_lookup_failure_logs_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    warnings: list[str] = []
    monkeypatch.setattr(
        gd.logger,
        "warning",
        lambda msg, *args: warnings.append(str(msg).format(*args)),
    )

    mock_service = MagicMock()
    mock_service.users.return_value.messages.return_value.list.return_value.execute.side_effect = (
        RuntimeError("insufficient scope")
    )
    mock_service.users.return_value.drafts.return_value.create.return_value.execute.return_value = {
        "id": "draft-warn",
        "message": {},
    }
    monkeypatch.setattr(
        "nanobot.agent.tools.gmail_auth.get_gmail_service",
        lambda _cfg: mock_service,
    )

    gd.create_gmail_draft(
        to="cust@example.com",
        subject="Question",
        body="Reply text",
        in_reply_to="orig@example.com",
        original_body="Original line",
        gmail_draft_config=_configured(),
    )

    assert any("lookup failed" in w.lower() for w in warnings)


def test_lookup_failure_falls_back_to_manual_reply_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    mock_service = MagicMock()
    mock_service.users.return_value.messages.return_value.list.return_value.execute.side_effect = RuntimeError(
        "api unavailable"
    )
    mock_service.users.return_value.drafts.return_value.create.return_value.execute.return_value = {
        "id": "draft-fallback",
        "message": {"threadId": "thread-fallback"},
    }
    monkeypatch.setattr(
        "nanobot.agent.tools.gmail_auth.get_gmail_service",
        lambda _cfg: mock_service,
    )

    result = gd.create_gmail_draft(
        to="cust@example.com",
        subject="Question",
        body="Reply text",
        in_reply_to="orig@example.com",
        thread_id="thread-fallback",
        original_body="Original line",
        gmail_draft_config=_configured(),
    )

    assert result["reply_in_thread"] is True
    raw = mock_service.users.return_value.drafts.return_value.create.call_args.kwargs["body"]["message"]["raw"]
    parsed = _decode_raw(raw)
    assert parsed["In-Reply-To"] == "<orig@example.com>"
    assert "> Original line" in parsed.get_payload(decode=True).decode()


def test_build_references_does_not_false_match_partial_id() -> None:
    refs = "<abc123@example.com>"
    out = gd._build_references(refs, "<abc@example.com>")
    assert out == "<abc123@example.com> <abc@example.com>"
