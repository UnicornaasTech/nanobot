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
from nanobot.channels.instagram.review_state import compose_chat_id
from nanobot.channels.instagram.runtime import (
    _MAX_BACKFILL_IMAGES,
    _THREAD_CONTEXT_LIMIT,
    ACTION_DISCARD,
    ACTION_SEND,
    CALLBACK_EDIT_MODAL,
    InstagramAccountConfig,
    InstagramChannel,
    InstagramConfig,
    _ParsedIgMessage,
)
from nanobot.channels.registry import discover_plugins
from nanobot.session.manager import SessionManager


def test_instagram_channel_package_is_discoverable() -> None:
    plugins = discover_plugins()
    assert "instagram" in plugins
    assert plugins["instagram"].name == "instagram"
    assert plugins["instagram"].load_channel_class() is InstagramChannel


def test_legacy_top_level_config_rejected() -> None:
    with pytest.raises(ValueError, match="accounts\\[\\]"):
        InstagramConfig.model_validate(
            {
                "enabled": True,
                "consentGranted": True,
                "pageAccessToken": "tok",
                "pageId": "PAGE1",
                "slackBotToken": "xoxb-test",
                "slackDraftChannel": "C01234567",
                "slackAppToken": "xapp-test-token",
            }
        )


def test_hyphenated_account_keys_register_distinct_webhook_routes() -> None:
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
                account_key="brand-a",
                page_id="PAGE_A",
                page_access_token="token_a",
                app_secret="secret_a",
                verify_token="verify_a",
            ),
            InstagramAccountConfig(
                account_key="brand_a",
                page_id="PAGE_B",
                page_access_token="token_b",
                app_secret="secret_b",
                verify_token="verify_b",
            ),
        ],
    )
    ch = InstagramChannel(cfg.model_dump(by_alias=True), bus)
    assert ch.app is not None
    rules = {rule.rule for rule in ch.app.url_map.iter_rules()}
    assert "/webhook/instagram/brand-a" in rules
    assert "/webhook/instagram/brand_a" in rules


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
        "/webhook/instagram/default",
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
        "/webhook/instagram/default",
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
    assert "Customer thread" in flat
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
        "nanobot.channels.instagram.runtime.get_slack_thread_ts",
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
        "nanobot.channels.instagram.runtime.get_slack_thread_ts",
        lambda sender: stored.get(sender),
    )
    monkeypatch.setattr(
        "nanobot.channels.instagram.runtime.set_slack_thread_ts",
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
    monkeypatch.setattr("nanobot.channels.instagram.runtime.consume_draft", lambda _chat: None)

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

    from nanobot.channels.instagram.review_state import InstagramDraftPayload

    monkeypatch.setattr(
        "nanobot.channels.instagram.runtime.consume_draft",
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

    def fake_publish(_account, _sender: str, _text: str, _raw: dict, **kwargs: object) -> None:
        nonlocal published
        published += 1

    ch._publish_inbound_sync = fake_publish  # type: ignore[method-assign]
    hello = _ParsedIgMessage(text="hello", media=[], markers=[])
    again = _ParsedIgMessage(text="hello again", media=[], markers=[])
    ch._ingest_inbound_dm(account, "u1", hello, message_id="m1", raw={})
    ch._ingest_inbound_dm(account, "u1", again, message_id="m1", raw={})
    assert published == 1
    assert "m1" in ch._seen_inbound_ids


def test_poll_conversations_ingests_customer_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    ingested: list[tuple[str, str, str]] = []

    def capture(account, sender: str, parsed: _ParsedIgMessage, *, message_id, raw):
        ingested.append((account.account_key, sender, parsed.text))

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

    monkeypatch.setattr("nanobot.channels.instagram.runtime.httpx.Client", FakeClient)
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

    monkeypatch.setattr("nanobot.channels.instagram.runtime.httpx.Client", FakeClient)
    ch._send_instagram_message("CUST", "hello", "acct_a")
    assert tokens == ["token_a"]


def test_parse_inbound_message_downloads_image(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    account = _sole_account(ch)
    monkeypatch.setattr(
        ch,
        "_download_attachment_url",
        lambda url, acc, *, file_id, att_type: f"/tmp/{file_id}.jpg",
    )
    parsed = ch._parse_inbound_message(
        {
            "text": "see this",
            "attachments": [{"type": "image", "payload": {"url": "https://cdn.example/a.jpg"}}],
        },
        account,
        file_id_prefix="mid1",
    )
    assert parsed is not None
    assert parsed.text == "see this"
    assert parsed.media == ["/tmp/mid1_0.jpg"]
    assert "[image:" in parsed.markers[0]


def test_parse_inbound_message_image_download_failure_marker() -> None:
    ch = _channel()
    account = _sole_account(ch)
    parsed = ch._parse_inbound_message(
        {
            "attachments": [{"type": "image", "payload": {"url": "https://cdn.example/a.jpg"}}],
        },
        account,
        file_id_prefix="mid2",
    )
    assert parsed is not None
    assert parsed.media == []
    assert parsed.markers == ["[image: download failed]"]


def test_parse_inbound_message_downloads_pdf_to_media(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    account = _sole_account(ch)
    monkeypatch.setattr(
        ch,
        "_download_attachment_url",
        lambda url, acc, *, file_id, att_type: f"/tmp/{file_id}.pdf",
    )
    parsed = ch._parse_inbound_message(
        {
            "text": "invoice",
            "attachments": [{"type": "file", "payload": {"url": "https://cdn.example/doc.pdf"}}],
        },
        account,
        file_id_prefix="mid3",
    )
    assert parsed is not None
    assert parsed.media == ["/tmp/mid3_0.pdf"]
    assert "saved to" in parsed.markers[0]


def test_parse_inbound_message_video_marker_without_media(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    account = _sole_account(ch)
    monkeypatch.setattr(
        ch,
        "_download_attachment_url",
        lambda url, acc, *, file_id, att_type: f"/tmp/{file_id}.mp4",
    )
    parsed = ch._parse_inbound_message(
        {
            "attachments": [{"type": "video", "payload": {"url": "https://cdn.example/v.mp4"}}],
        },
        account,
        file_id_prefix="mid4",
    )
    assert parsed is not None
    assert parsed.media == []
    assert "[video:" in parsed.markers[0]


def test_webhook_ingests_image_only_message(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    ingested: list[_ParsedIgMessage] = []

    def capture(_account, _sender: str, parsed: _ParsedIgMessage, *, message_id, raw):
        ingested.append(parsed)

    monkeypatch.setattr(ch, "_ingest_inbound_dm", capture)
    monkeypatch.setattr(
        ch,
        "_parse_inbound_message",
        lambda message, account, *, file_id_prefix: _ParsedIgMessage(
            text="",
            media=["/tmp/photo.jpg"],
            markers=["[image: photo.jpg]"],
        ),
    )
    ch._handle_ig_payload(
        {
            "entry": [
                {
                    "id": "PAGE1",
                    "messaging": [
                        {
                            "sender": {"id": "USER1"},
                            "message": {
                                "mid": "m-img",
                                "attachments": [
                                    {"type": "image", "payload": {"url": "https://x"}},
                                ],
                            },
                        },
                    ],
                },
            ],
        },
    )
    assert len(ingested) == 1
    assert ingested[0].media == ["/tmp/photo.jpg"]


def test_backfill_skipped_when_session_has_history(tmp_path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    sessions = SessionManager(workspace)
    chat_id = compose_chat_id("default", "USER1")
    session = sessions.get_or_create(f"instagram:{chat_id}")
    session.add_message("user", "prior turn")
    sessions.save(session)

    ch = _channel()
    ch._session_manager = sessions
    ch._remember_thread_backfill_attempt(chat_id)

    model_text, model_media = ch._maybe_thread_backfill(
        _sole_account(ch),
        "USER1",
        "new message",
        [],
        exclude_message_id="mid-new",
    )
    assert model_text == "new message"
    assert model_media == []


def test_backfill_includes_prior_context(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    sessions = SessionManager(workspace)
    ch = _channel()
    ch._session_manager = sessions
    account = _sole_account(ch)

    prior = [
        {"id": "old1", "message": "first", "from": {"id": "USER1"}, "created_time": "1"},
        {"id": "old2", "message": "second", "from": {"id": "USER1"}, "created_time": "2"},
    ]
    monkeypatch.setattr(ch, "_fetch_customer_thread_messages", lambda acc, cid: prior)

    model_text, model_media = ch._maybe_thread_backfill(
        account,
        "USER1",
        "latest",
        [],
        exclude_message_id="mid-new",
    )
    assert "Instagram thread context before this message:" in model_text
    assert "first" in model_text
    assert "second" in model_text
    assert "Current message:\nlatest" in model_text
    assert model_media == []


def test_format_thread_backfill_caps_messages_and_images(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    account = _sole_account(ch)
    messages = []
    for index in range(_THREAD_CONTEXT_LIMIT + 5):
        messages.append({
            "id": f"mid{index}",
            "message": f"msg {index}",
            "from": {"id": "USER1"},
            "created_time": str(index),
            "attachments": [
                {"type": "image", "payload": {"url": f"https://cdn/{index}.jpg"}},
            ],
        })
    monkeypatch.setattr(
        ch,
        "_download_attachment_url",
        lambda url, acc, *, file_id, att_type: f"/tmp/{file_id}.jpg",
    )
    context_text, context_media = ch._format_thread_backfill(
        account,
        messages,
        exclude_message_id=None,
    )
    assert context_text.count("- customer:") == _THREAD_CONTEXT_LIMIT
    assert len(context_media) == _MAX_BACKFILL_IMAGES


def test_ingest_denied_when_not_in_allow_from() -> None:
    bus = MessageBus()
    cfg = InstagramConfig(
        enabled=True,
        consent_granted=True,
        use_webhook=False,
        slack_bot_token="xoxb-test",
        slack_draft_channel="C01234567",
        slack_app_token="xapp-test-token",
        allow_from=["OTHER_USER"],
        accounts=[
            InstagramAccountConfig(
                account_key="default",
                page_id="PAGE1",
                page_access_token="token",
            ),
        ],
    )
    ch = InstagramChannel(cfg.model_dump(by_alias=True), bus)
    published: list[str] = []

    def fake_publish(*_args, **_kwargs) -> None:
        published.append("yes")

    ch._publish_inbound_sync = fake_publish  # type: ignore[method-assign]
    parsed = _ParsedIgMessage(text="hello", media=[], markers=[])
    ch._ingest_inbound_dm(
        _sole_account(ch),
        "DENIED_USER",
        parsed,
        message_id="m-deny",
        raw={},
    )
    assert published == []


def test_slack_thread_display_splits_by_message_id(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    account = _sole_account(ch)
    messages = [
        {"id": "m1", "message": "older", "from": {"id": "U1"}, "created_time": "1"},
        {"id": "m2", "message": "middle", "from": {"id": "U1"}, "created_time": "2"},
        {
            "id": "m3",
            "message": "latest",
            "from": {"id": "U1"},
            "created_time": "3",
            "attachments": [{"type": "image", "payload": {"url": "https://x"}}],
        },
    ]
    monkeypatch.setattr(ch, "_fetch_customer_thread_messages", lambda acc, cid: messages)
    display = ch._build_slack_customer_thread_display(
        account,
        "U1",
        "[image: saved.jpg — saved to /tmp/saved.jpg]\nlatest",
        current_message_id="m3",
    )
    assert "older" in display
    assert "middle" in display
    assert "*Current message:*" in display
    assert "saved.jpg" in display
    assert display.index("older") < display.index("middle")
    assert display.index("middle") < display.index("*Current message:*")


def test_post_review_shows_prior_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    ch = _channel()
    captured: dict = {}

    def fake_slack_api(method: str, body: dict, token: str) -> dict:
        captured["body"] = body
        return {"ok": True, "ts": "500.001"}

    monkeypatch.setattr(ch, "_slack_api", fake_slack_api)
    monkeypatch.setattr(
        ch,
        "_build_slack_customer_thread_display",
        lambda account, customer_id, current, **kwargs: (
            "*Recent messages:*\n"
            "• older one\n"
            "• middle\n"
            "*Current message:*\n"
            f"{current}"
        ),
    )
    ch.post_review_to_slack(
        compose_chat_id("default", "uid5"),
        "latest",
        "draft",
        review_mode="tool_draft",
        allow_send=True,
        account_key="default",
    )
    flat = json.dumps(captured["body"]["blocks"])
    assert "Recent messages" in flat
    assert "older one" in flat
    assert "latest" in flat


@pytest.mark.asyncio
async def test_publish_inbound_includes_media_and_original_text() -> None:
    ch = _channel()
    ch._loop = asyncio.get_running_loop()
    captured: list[dict] = []

    async def capture(msg):
        captured.append({
            "media": list(msg.media),
            "original": msg.metadata.get("instagram_original_dm"),
            "content_tail": msg.content.split("\n", 1)[-1],
        })

    ch.bus.publish_inbound = capture  # type: ignore[method-assign]
    account = _sole_account(ch)
    ch._publish_inbound_sync(
        account,
        "CUST1",
        "Instagram thread context before this message:\n-old\n\nCurrent message:\nhello",
        {"test": True},
        media=["/tmp/a.jpg"],
        original_text="hello",
        message_id="mid-1",
    )
    for _ in range(50):
        if captured:
            break
        await asyncio.sleep(0.02)
    assert captured[0]["media"] == ["/tmp/a.jpg"]
    assert captured[0]["original"] == "hello"
    assert captured[0]["content_tail"].startswith("Instagram thread context")
