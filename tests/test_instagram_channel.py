"""Instagram channel behavior without Meta/Slack integrations."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import time
from types import SimpleNamespace

import pytest
from slack_sdk.socket_mode.response import SocketModeResponse

pytest.importorskip("flask")

from nanobot.bus.queue import MessageBus
from nanobot.channels.instagram import (
    ACTION_DISCARD,
    ACTION_SEND,
    CALLBACK_EDIT_MODAL,
    InstagramChannel,
    InstagramConfig,
)


def test_send_message_is_disabled() -> None:
    ch = InstagramChannel.__new__(InstagramChannel)
    with pytest.raises(NotImplementedError, match="Slack"):
        ch.send_message("some_user", "some text")


def _channel() -> InstagramChannel:
    bus = MessageBus()
    cfg = InstagramConfig(
        enabled=True,
        consent_granted=True,
        app_secret="meta_secret",
        verify_token="verify_me",
        page_access_token="page_token",
        slack_bot_token="xoxb-test",
        slack_draft_channel="C01234567",
        slack_app_token="xapp-test-token",
    )
    return InstagramChannel(cfg.model_dump(by_alias=True), bus)


class _FakeSocketClient:
    def __init__(self) -> None:
        self.acks: list[str] = []

    async def send_socket_mode_response(self, resp: SocketModeResponse) -> None:
        self.acks.append(resp.envelope_id)


def test_meta_signature_rejects_bad_sig() -> None:
    ch = _channel()
    assert ch.app is not None
    client = ch.app.test_client()
    body = b'{"object":"instagram","entry":[]}'
    rv = client.post(
        "/webhook/instagram",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": "sha256=deadbeef",
        },
    )
    assert rv.status_code == 401


def test_meta_signature_accepts_valid_sig() -> None:
    ch = _channel()
    client = ch.app.test_client()
    body = b'{"object":"instagram","entry":[]}'
    sig = "sha256=" + hmac.new(b"meta_secret", body, hashlib.sha256).hexdigest()
    rv = client.post(
        "/webhook/instagram",
        data=body,
        headers={"Content-Type": "application/json", "X-Hub-Signature-256": sig},
    )
    assert rv.status_code == 200


async def test_socket_interactive_ack_then_handle_send(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    sends: list[tuple[str, str]] = []

    def capture_send(rid: str, text: str) -> bool:
        sends.append((rid, text))
        return True

    monkeypatch.setattr(ch, "_send_instagram_message", capture_send)
    monkeypatch.setattr(ch, "_slack_api", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(ch, "_update_slack_message", lambda **k: None)

    payload = {
        "type": "block_actions",
        "user": {"id": "U1"},
        "channel": {"id": "C1"},
        "message": {"ts": "1.2"},
        "actions": [
            {
                "action_id": ACTION_SEND,
                "value": json.dumps({
                    "sender_id": "IG123",
                    "draft": "go",
                    "original": "hi",
                }),
            },
        ],
    }
    fake = _FakeSocketClient()
    req = SimpleNamespace(type="interactive", envelope_id="env-1", payload=payload)
    await ch._on_instagram_slack_socket_request(fake, req)  # type: ignore[arg-type]
    assert fake.acks == ["env-1"]
    for _ in range(100):
        if sends:
            break
        await asyncio.sleep(0.02)
    assert sends == [("IG123", "go")]


async def test_socket_interactive_ack_discard(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    called: list[str] = []

    def no_send(_rid: str, _text: str) -> bool:
        called.append("send")
        return True

    updates: list[dict] = []

    monkeypatch.setattr(ch, "_send_instagram_message", no_send)
    monkeypatch.setattr(ch, "_update_slack_message", lambda **kw: updates.append(kw))

    payload = {
        "type": "block_actions",
        "user": {"id": "U1"},
        "channel": {"id": "C1"},
        "message": {"ts": "1.2"},
        "actions": [
            {
                "action_id": ACTION_DISCARD,
                "value": json.dumps({"sender_id": "IG9", "original": "x"}),
            },
        ],
    }
    fake = _FakeSocketClient()
    req = SimpleNamespace(type="interactive", envelope_id="e2", payload=payload)
    await ch._on_instagram_slack_socket_request(fake, req)  # type: ignore[arg-type]
    assert fake.acks == ["e2"]
    for _ in range(50):
        if updates:
            break
        await asyncio.sleep(0.02)
    assert not called
    assert updates and "Discarded" in updates[0].get("status", "")


async def test_socket_non_interactive_does_not_ack() -> None:
    ch = _channel()
    fake = _FakeSocketClient()
    req = SimpleNamespace(type="events_api", envelope_id="e3", payload={})
    await ch._on_instagram_slack_socket_request(fake, req)  # type: ignore[arg-type]
    assert fake.acks == []


async def test_socket_interactive_handler_errors_are_logged_and_acked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ch = _channel()
    fake = _FakeSocketClient()
    payload = {"type": "block_actions", "actions": []}
    req = SimpleNamespace(type="interactive", envelope_id="e4", payload=payload)

    def boom(_payload: dict) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(ch, "_handle_slack_action", boom)
    await ch._on_instagram_slack_socket_request(fake, req)  # type: ignore[arg-type]
    assert fake.acks == ["e4"]


def test_post_draft_builds_correct_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    captured: dict = {}

    def fake_slack_api(method: str, body: dict, token: str) -> dict:
        captured["method"] = method
        captured["body"] = body
        return {"ok": True}

    monkeypatch.setattr(ch, "_slack_api", fake_slack_api)
    ch.post_draft_to_slack("uid1", "hello", "draft text", "Name")
    blocks = captured["body"]["blocks"]
    flat = json.dumps(blocks)
    assert ACTION_SEND in flat
    assert "ig_draft_edit_send" in flat
    assert ACTION_DISCARD in flat


def test_edit_modal_submit_sends_edited_text(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    sends: list[str] = []

    def capture_send(rid: str, text: str) -> bool:
        sends.append(text)
        return True

    monkeypatch.setattr(ch, "_send_instagram_message", capture_send)
    monkeypatch.setattr(ch, "_slack_api", lambda *a, **k: {"ok": True})

    payload = {
        "type": "view_submission",
        "user": {"id": "U1"},
        "view": {
            "callback_id": CALLBACK_EDIT_MODAL,
            "private_metadata": json.dumps({
                "sender_id": "IG1",
                "slack_channel": "C1",
                "slack_ts": "9.9",
                "original": "orig",
            }),
            "state": {
                "values": {
                    "edited_reply_block": {
                        "edited_reply_input": {"value": "edited body"},
                    },
                },
            },
        },
    }
    ch._handle_edit_modal_submit(payload)
    time.sleep(0.15)
    assert sends == ["edited body"]


def test_poll_interval_clamped() -> None:
    assert InstagramChannel._clamp_poll_interval(120) == 60
    assert InstagramChannel._clamp_poll_interval(60) == 60


def test_poll_enabled_requires_page_id() -> None:
    ch = _channel()
    ch.config.page_id = ""
    assert ch._poll_enabled() is False
    ch.config.page_id = "PAGE1"
    assert ch._poll_enabled() is True


def test_ingest_dedupes_by_message_id() -> None:
    ch = _channel()
    published = 0

    def fake_publish(_sender: str, _text: str, _raw: dict) -> None:
        nonlocal published
        published += 1

    ch._publish_inbound_sync = fake_publish  # type: ignore[method-assign]
    ch._ingest_inbound_dm("u1", "hello", message_id="m1", raw={})
    ch._ingest_inbound_dm("u1", "hello again", message_id="m1", raw={})
    assert published == 1
    assert "m1" in ch._seen_inbound_ids


def test_poll_conversations_ingests_customer_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    ch.config.page_id = "PAGE1"
    ingested: list[tuple[str, str]] = []

    def capture(sender: str, text: str, *, message_id, raw):
        ingested.append((sender, text))

    monkeypatch.setattr(ch, "_ingest_inbound_dm", capture)

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "data": [
                    {
                        "messages": {
                            "data": [
                                {
                                    "id": "mid1",
                                    "message": "hi there",
                                    "from": {"id": "USER1"},
                                },
                                {
                                    "id": "mid2",
                                    "message": "page reply",
                                    "from": {"id": "PAGE1"},
                                },
                            ],
                        },
                    },
                ],
            }

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, params=None):
            assert "PAGE1" in url
            return FakeResponse()

    monkeypatch.setattr("nanobot.channels.instagram.httpx.Client", FakeClient)
    ch._poll_conversations_once()
    assert ingested == [("USER1", "hi there")]
