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
    InstagramAccountConfig,
    InstagramChannel,
    InstagramConfig,
)
from nanobot.channels.instagram_review_state import compose_chat_id


def test_send_message_is_disabled() -> None:
    ch = InstagramChannel.__new__(InstagramChannel)
    with pytest.raises(NotImplementedError, match="Slack"):
        ch.send_message("some_user", "some text")


def _channel(*, page_id: str = "PAGE1") -> InstagramChannel:
    bus = MessageBus()
    cfg = InstagramConfig(
        enabled=True,
        consent_granted=True,
        use_webhook=True,
        app_secret="meta_secret",
        verify_token="verify_me",
        page_access_token="page_token",
        page_id=page_id,
        slack_bot_token="xoxb-test",
        slack_draft_channel="C01234567",
        slack_app_token="xapp-test-token",
        accounts=[
            InstagramAccountConfig(
                account_key="default",
                label="Default",
                page_id=page_id,
                page_access_token="page_token",
                app_secret="meta_secret",
                verify_token="verify_me",
            ),
        ],
    )
    return InstagramChannel(cfg.model_dump(by_alias=True), bus)


def _sole_account(ch: InstagramChannel) -> InstagramAccountConfig:
    return ch._account_list()[0]


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

    def capture_send(rid: str, text: str, account_key: str = "") -> bool:
        sends.append((rid, text, account_key))
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
                    "account_key": "default",
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
    assert sends == [("IG123", "go", "default")]


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
        return {"ok": True, "ts": "100.001"}

    monkeypatch.setattr(ch, "_slack_api", fake_slack_api)
    ch.post_draft_to_slack(
        compose_chat_id("default", "uid1"),
        "hello",
        "draft text",
        "Name",
        account_key="default",
        account_label="Default",
    )
    blocks = captured["body"]["blocks"]
    flat = json.dumps(blocks)
    assert ACTION_SEND in flat
    assert "ig_draft_edit_send" in flat
    assert ACTION_DISCARD in flat
    assert "Customer message" in flat
    assert "hello" in flat
    assert captured["body"].get("thread_ts") == "100.001"


def test_post_review_no_reply_is_edit_only(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    captured: dict = {}

    def fake_slack_api(method: str, body: dict, token: str) -> dict:
        captured["method"] = method
        captured["body"] = body
        return {"ok": True, "ts": "200.001"}

    monkeypatch.setattr(ch, "_slack_api", fake_slack_api)
    ch.post_review_to_slack(
        compose_chat_id("default", "uid2"),
        "customer says hi",
        "",
        review_mode="no_reply_suggested",
        allow_send=False,
        account_key="default",
    )
    blocks = captured["body"]["blocks"]
    flat = json.dumps(blocks)
    assert ACTION_SEND not in flat
    assert "ig_draft_edit_send" in flat
    assert ACTION_DISCARD in flat
    assert "no reply suggested" in flat.lower()
    assert "customer says hi" in flat


def test_post_review_long_draft_disables_send(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    captured: dict = {}

    def fake_slack_api(method: str, body: dict, token: str) -> dict:
        captured["method"] = method
        captured["body"] = body
        return {"ok": True, "ts": "210.001"}

    monkeypatch.setattr(ch, "_slack_api", fake_slack_api)
    ch.post_review_to_slack(
        compose_chat_id("default", "uid2"),
        "customer says hi",
        "x" * 5000,
        review_mode="tool_draft",
        allow_send=True,
        account_key="default",
    )
    flat = json.dumps(captured["body"]["blocks"])
    assert ACTION_SEND not in flat
    assert "Edit & Send" in flat
    assert "payload limits" in flat


def test_post_review_reuses_slack_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    calls: list[dict] = []

    def fake_slack_api(method: str, body: dict, token: str) -> dict:
        calls.append(body)
        if "thread_ts" not in body:
            return {"ok": True, "ts": "300.000"}
        return {"ok": True, "ts": "300.001"}

    monkeypatch.setattr(ch, "_slack_api", fake_slack_api)
    monkeypatch.setattr(
        "nanobot.channels.instagram.get_slack_thread_ts",
        lambda _sender: "300.000",
    )

    chat = compose_chat_id("default", "uid3")
    ch.post_review_to_slack(
        chat,
        "first customer message",
        "draft one",
        review_mode="tool_draft",
        allow_send=True,
        account_key="default",
    )
    ch.post_review_to_slack(
        chat,
        "second customer message",
        "draft two",
        review_mode="tool_draft",
        allow_send=True,
        account_key="default",
    )

    assert len(calls) == 2
    assert calls[0]["thread_ts"] == "300.000"
    assert calls[1]["thread_ts"] == "300.000"
    assert "first customer message" in json.dumps(calls[0]["blocks"])
    assert "second customer message" in json.dumps(calls[1]["blocks"])


def test_post_review_creates_thread_anchor_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    calls: list[dict] = []
    stored: dict[str, str] = {}

    def fake_slack_api(method: str, body: dict, token: str) -> dict:
        calls.append(body)
        if "thread_ts" not in body:
            return {"ok": True, "ts": "400.000"}
        return {"ok": True, "ts": "400.001"}

    monkeypatch.setattr(ch, "_slack_api", fake_slack_api)
    monkeypatch.setattr(
        "nanobot.channels.instagram.get_slack_thread_ts",
        lambda sender: stored.get(sender),
    )
    monkeypatch.setattr(
        "nanobot.channels.instagram.set_slack_thread_ts",
        lambda sender, ts: stored.__setitem__(sender, ts),
    )

    chat4 = compose_chat_id("default", "uid4")
    ch.post_review_to_slack(
        chat4,
        "hello there",
        "draft",
        review_mode="tool_draft",
        allow_send=True,
        account_key="default",
    )

    assert len(calls) == 2
    assert "thread_ts" not in calls[0]
    assert calls[1]["thread_ts"] == "400.000"
    assert stored[chat4] == "400.000"


@pytest.mark.asyncio
async def test_send_posts_no_reply_card_when_tool_not_used(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    posted: list[dict] = []

    def capture_post(*args, **kwargs) -> None:
        posted.append({"args": args, "kwargs": kwargs})

    monkeypatch.setattr(ch, "post_review_to_slack", capture_post)
    monkeypatch.setattr("nanobot.channels.instagram.consume_draft", lambda _chat: None)

    from nanobot.bus.events import OutboundMessage

    await ch.send(
        OutboundMessage(
            channel="instagram",
            chat_id="IG55",
            content="",
            metadata={"instagram_original_dm": "Need help?"},
        )
    )

    assert len(posted) == 1
    assert posted[0]["kwargs"]["review_mode"] == "no_reply_suggested"
    assert posted[0]["kwargs"]["allow_send"] is False
    assert posted[0]["args"][1] == "Need help?"


@pytest.mark.asyncio
async def test_send_posts_tool_draft_card_when_tool_used(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    posted: list[dict] = []

    def capture_post(*args, **kwargs) -> None:
        posted.append({"args": args, "kwargs": kwargs})

    monkeypatch.setattr(ch, "post_review_to_slack", capture_post)

    from nanobot.channels.instagram_review_state import InstagramDraftPayload

    monkeypatch.setattr(
        "nanobot.channels.instagram.consume_draft",
        lambda _chat: InstagramDraftPayload(draft_text="Proposed reply", review_notes="note"),
    )

    from nanobot.bus.events import OutboundMessage

    await ch.send(
        OutboundMessage(
            channel="instagram",
            chat_id="IG66",
            content="ignored assistant text",
            metadata={"instagram_original_dm": "Where is my order?"},
        )
    )

    assert len(posted) == 1
    assert posted[0]["kwargs"]["review_mode"] == "tool_draft"
    assert posted[0]["kwargs"]["allow_send"] is True
    assert posted[0]["args"][2] == "Proposed reply"
    assert posted[0]["args"][1] == "Where is my order?"


def test_edit_modal_submit_sends_edited_text(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    sends: list[str] = []

    def capture_send(rid: str, text: str, account_key: str = "") -> bool:
        sends.append((text, account_key))
        return True

    monkeypatch.setattr(ch, "_send_instagram_message", capture_send)
    monkeypatch.setattr(ch, "_slack_api", lambda *a, **k: {"ok": True})

    payload = {
        "type": "view_submission",
        "user": {"id": "U1"},
        "view": {
            "callback_id": CALLBACK_EDIT_MODAL,
            "private_metadata": json.dumps({
                "account_key": "default",
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
    assert sends == [("edited body", "default")]


def test_poll_interval_clamped() -> None:
    assert InstagramChannel._clamp_poll_interval(120) == 60
    assert InstagramChannel._clamp_poll_interval(60) == 60


def test_poll_enabled_requires_page_id() -> None:
    ch = _channel(page_id="")
    assert ch._poll_enabled() is False
    _sole_account(ch).page_id = "PAGE1"
    assert ch._poll_enabled() is True


def test_ingest_dedupes_by_message_id() -> None:
    ch = _channel()
    published = 0
    account = _sole_account(ch)

    def fake_publish(_account, _sender: str, _text: str, _raw: dict) -> None:
        nonlocal published
        published += 1

    ch._publish_inbound_sync = fake_publish  # type: ignore[method-assign]
    ch._ingest_inbound_dm(account, "u1", "hello", message_id="m1", raw={})
    ch._ingest_inbound_dm(account, "u1", "hello again", message_id="m1", raw={})
    assert published == 1
    assert "m1" in ch._seen_inbound_ids


def test_poll_conversations_ingests_customer_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    ingested: list[tuple[str, str, str]] = []

    def capture(account, sender: str, text: str, *, message_id, raw):
        ingested.append((account.account_key, sender, text))

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
    ch._poll_conversations_for_account(_sole_account(ch))
    assert ingested == [("default", "USER1", "hi there")]


def test_per_account_webhook_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    bus = MessageBus()
    cfg = InstagramConfig(
        enabled=True,
        consent_granted=True,
        use_webhook=True,
        slack_bot_token="xoxb-test",
        slack_draft_channel="C01234567",
        slack_app_token="xapp-test-token",
        accounts=[
            InstagramAccountConfig(
                account_key="brand_a",
                page_id="PAGE_A",
                page_access_token="token_a",
                app_secret="secret_a",
                verify_token="verify_a",
            ),
            InstagramAccountConfig(
                account_key="brand_b",
                page_id="PAGE_B",
                page_access_token="token_b",
                app_secret="secret_b",
                verify_token="verify_b",
            ),
        ],
    )
    ch = InstagramChannel(cfg.model_dump(by_alias=True), bus)
    assert ch.app is not None
    client = ch.app.test_client()
    body = b'{"object":"instagram","entry":[]}'
    bad_sig = "sha256=deadbeef"
    rv = client.post(
        "/webhook/instagram/brand_a",
        data=body,
        headers={"Content-Type": "application/json", "X-Hub-Signature-256": bad_sig},
    )
    assert rv.status_code == 401
    good_sig = "sha256=" + hmac.new(b"secret_a", body, hashlib.sha256).hexdigest()
    rv = client.post(
        "/webhook/instagram/brand_a",
        data=body,
        headers={"Content-Type": "application/json", "X-Hub-Signature-256": good_sig},
    )
    assert rv.status_code == 200


@pytest.mark.asyncio
async def test_publish_inbound_uses_namespaced_chat_id() -> None:
    ch = _channel()
    ch._loop = asyncio.get_running_loop()
    published: list[str] = []

    async def capture(msg):
        published.append(msg.chat_id)

    ch.bus.publish_inbound = capture  # type: ignore[method-assign]
    account = _sole_account(ch)
    ch._publish_inbound_sync(account, "CUST1", "hello", {"test": True})
    for _ in range(50):
        if published:
            break
        await asyncio.sleep(0.02)
    assert published == [compose_chat_id("default", "CUST1")]


@pytest.mark.asyncio
async def test_same_sender_two_accounts_isolated() -> None:
    bus = MessageBus()
    cfg = InstagramConfig(
        enabled=True,
        consent_granted=True,
        use_webhook=False,
        poll_interval_seconds=60,
        slack_bot_token="xoxb-test",
        slack_draft_channel="C01234567",
        slack_app_token="xapp-test-token",
        accounts=[
            InstagramAccountConfig(
                account_key="acct_a",
                page_id="PAGE_A",
                page_access_token="token_a",
            ),
            InstagramAccountConfig(
                account_key="acct_b",
                page_id="PAGE_B",
                page_access_token="token_b",
            ),
        ],
    )
    ch = InstagramChannel(cfg.model_dump(by_alias=True), bus)
    ch._loop = asyncio.get_running_loop()
    chat_ids: list[str] = []

    async def capture(msg):
        chat_ids.append(msg.chat_id)

    ch.bus.publish_inbound = capture  # type: ignore[method-assign]
    ch._publish_inbound_sync(ch._get_account("acct_a"), "SAME", "hi", {})
    ch._publish_inbound_sync(ch._get_account("acct_b"), "SAME", "hi", {})
    for _ in range(50):
        if len(chat_ids) >= 2:
            break
        await asyncio.sleep(0.02)
    assert chat_ids == [
        compose_chat_id("acct_a", "SAME"),
        compose_chat_id("acct_b", "SAME"),
    ]
    assert chat_ids[0] != chat_ids[1]


def test_send_uses_matching_account_token(monkeypatch: pytest.MonkeyPatch) -> None:
    bus = MessageBus()
    cfg = InstagramConfig(
        enabled=True,
        consent_granted=True,
        use_webhook=False,
        slack_bot_token="xoxb-test",
        slack_draft_channel="C01234567",
        slack_app_token="xapp-test-token",
        accounts=[
            InstagramAccountConfig(
                account_key="acct_a",
                page_id="PAGE_A",
                page_access_token="token_a",
            ),
        ],
    )
    ch = InstagramChannel(cfg.model_dump(by_alias=True), bus)
    tokens: list[str] = []

    class FakeResponse:
        status_code = 200
        text = "ok"

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, *, params=None, json=None):
            tokens.append((params or {}).get("access_token", ""))
            return FakeResponse()

    monkeypatch.setattr("nanobot.channels.instagram.httpx.Client", FakeClient)
    ch._send_instagram_message("CUST", "hello", "acct_a")
    assert tokens == ["token_a"]
