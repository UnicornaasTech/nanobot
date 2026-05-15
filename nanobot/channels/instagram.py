"""
Instagram DM channel for nanobot.

Incoming DMs are published to the agent; outbound assistant text is posted to
Slack for human review (Send / Edit & Send / Discard). Only Slack button
handlers call the Instagram send API — not the agent.

Official references (verify behavior against current Meta / Slack docs):

- Instagram Messaging webhooks (GET verify, POST events, ``X-Hub-Signature-256``):
  https://developers.facebook.com/docs/messenger-platform/instagram/features/webhook/
- Meta webhooks overview:
  https://developers.facebook.com/docs/messenger-platform/webhooks/
- Send API (``POST /me/messages`` with Page access token):
  https://developers.facebook.com/docs/messenger-platform/instagram/features/send-message/
- Page conversations (poll fallback, ``platform=INSTAGRAM``):
  https://developers.facebook.com/docs/graph-api/reference/page/conversations/
- Slack Socket Mode (interactive payloads for draft approvals):
  https://api.slack.com/apis/connections/socket
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import threading
from contextlib import suppress
from typing import Any

import httpx
from pydantic import Field
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.socket_mode.websockets import SocketModeClient
from slack_sdk.web.async_client import AsyncWebClient

from nanobot.bus.events import InboundMessage, OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.channels.base import BaseChannel
from nanobot.config.schema import Base

ACTION_SEND = "ig_draft_send"
ACTION_EDIT_SEND = "ig_draft_edit_send"
ACTION_DISCARD = "ig_draft_discard"
CALLBACK_EDIT_MODAL = "ig_edit_modal_submit"
_POLL_INTERVAL_MIN = 5
_POLL_INTERVAL_MAX = 60
_MAX_SEEN_INBOUND_IDS = 50_000
_GRAPH_API = "https://graph.facebook.com/v19.0"


class InstagramConfig(Base):
    """Instagram + Slack draft-review configuration."""

    enabled: bool = False
    consent_granted: bool = False
    streaming: bool = False

    app_secret: str = ""
    verify_token: str = ""
    page_access_token: str = ""
    page_id: str = ""  # Facebook Page ID — required for poll inbound / fallback
    ig_user_id: str = ""  # informational / skip self-messages in poll mode

    use_webhook: bool = True  # Meta push (immediate) to /webhook/instagram
    poll_fallback_enabled: bool = True  # also poll every poll_interval_seconds when page_id set
    poll_interval_seconds: int = 60  # max 60s between poll checks

    slack_bot_token: str = ""
    slack_draft_channel: str = ""
    slack_app_token: str = ""

    webhook_host: str = "0.0.0.0"
    webhook_port: int = 5005

    allow_from: list[str] = Field(default_factory=lambda: ["*"])


class InstagramChannel(BaseChannel):
    """Instagram DMs in, Slack-reviewed drafts out; Meta send only from human actions."""

    name = "instagram"
    display_name = "Instagram"
    _POLL_INTERVAL_MIN = _POLL_INTERVAL_MIN
    _POLL_INTERVAL_MAX = _POLL_INTERVAL_MAX
    _MAX_SEEN_INBOUND_IDS = _MAX_SEEN_INBOUND_IDS

    def __init__(self, config: Any, bus: MessageBus):
        if isinstance(config, dict):
            config = InstagramConfig.model_validate(config)
        super().__init__(config, bus)
        self.config: InstagramConfig = config
        self.app: Any = None
        self._flask_import_error: Exception | None = None
        self._httpd: Any = None
        self._server_thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._poll_task: asyncio.Task | None = None
        self._socket_task: asyncio.Task | None = None
        self._web_client: AsyncWebClient | None = None
        self._socket_client: SocketModeClient | None = None
        self._seen_inbound_ids: set[str] = set()
        self._setup_app()

    @classmethod
    def default_config(cls) -> dict[str, Any]:
        return InstagramConfig().model_dump(by_alias=True)

    @classmethod
    def _clamp_poll_interval(cls, seconds: int) -> int:
        return max(cls._POLL_INTERVAL_MIN, min(cls._POLL_INTERVAL_MAX, int(seconds)))

    def _poll_enabled(self) -> bool:
        if not self.config.page_id:
            return False
        if int(self.config.poll_interval_seconds) <= 0:
            return False
        if not self.config.use_webhook:
            return True
        return self.config.poll_fallback_enabled

    def _remember_inbound_id(self, message_id: str) -> None:
        self._seen_inbound_ids.add(message_id)
        if len(self._seen_inbound_ids) > self._MAX_SEEN_INBOUND_IDS:
            self._seen_inbound_ids = set(list(self._seen_inbound_ids)[len(self._seen_inbound_ids) // 2 :])

    def _ingest_inbound_dm(
        self,
        sender_id: str,
        text: str,
        *,
        message_id: str | None,
        raw: dict[str, Any],
    ) -> None:
        if message_id:
            if message_id in self._seen_inbound_ids:
                return
            self._remember_inbound_id(message_id)
        preview = text[:80] + "..." if len(text) > 80 else text
        self.logger.info("Instagram DM from {}: {}", sender_id, preview)
        self._publish_inbound_sync(sender_id, text, raw)

    def _setup_app(self) -> None:
        try:
            from flask import Flask, Response, jsonify, request
        except ImportError as e:
            self._flask_import_error = e
            return

        self.app = Flask(__name__)

        @self.app.route("/webhook/instagram", methods=["GET"])
        def ig_verify():
            mode = request.args.get("hub.mode")
            token = request.args.get("hub.verify_token")
            challenge = request.args.get("hub.challenge")
            if mode == "subscribe" and token == self.config.verify_token and challenge is not None:
                self.logger.info("Instagram webhook verified.")
                # Meta expects the raw hub.challenge string as the response body (200 OK).
                return Response(str(challenge), status=200, mimetype="text/plain")
            return Response("Forbidden", status=403, mimetype="text/plain")

        @self.app.route("/webhook/instagram", methods=["POST"])
        def ig_receive():
            if not self._verify_meta_signature(request):
                return "Unauthorized", 401
            payload = request.get_json(force=True)
            self._handle_ig_payload(payload)
            return jsonify({"status": "ok"}), 200

    def send_message(self, *args: Any, **kwargs: Any) -> None:
        """Spec / legacy name — direct Instagram send is never exposed to the agent."""
        raise NotImplementedError(
            "Direct Instagram send is disabled. "
            "Drafts go to Slack; humans send via the Approve button.",
        )

    async def send(self, msg: OutboundMessage) -> None:
        """Post agent reply to Slack for review (never sends to Instagram)."""
        md = msg.metadata or {}
        if md.get("_progress"):
            return
        if md.get("_turn_end") or md.get("_session_updated"):
            return
        if md.get("_stream_delta") or md.get("_stream_end"):
            return

        text = (msg.content or "").strip()
        if not text:
            return

        original = md.get("instagram_original_dm")
        if not isinstance(original, str):
            original = "(original DM not captured — check inbound metadata)"

        await asyncio.to_thread(
            self.post_draft_to_slack,
            msg.chat_id,
            original,
            text,
            str(md.get("instagram_sender_name") or ""),
        )

    async def start(self) -> None:
        if not self.config.consent_granted:
            self.logger.warning(
                "Instagram channel disabled: consent_granted is false. "
                "Set channels.instagram.consentGranted=true after explicit permission.",
            )
            return
        if self.config.use_webhook:
            if self._flask_import_error is not None:
                self.logger.error(
                    "Instagram Meta webhook requires Flask (pip install 'nanobot-ai[instagram]'): {}",
                    self._flask_import_error,
                )
                return
            if self.app is None:
                self.logger.error("Flask app not initialized")
                return
        missing = [
            k
            for k, v in (
                ("page_access_token", self.config.page_access_token),
                ("slack_bot_token", self.config.slack_bot_token),
                ("slack_draft_channel", self.config.slack_draft_channel),
                ("slack_app_token", self.config.slack_app_token),
            )
            if not v
        ]
        if self.config.use_webhook:
            for k, v in (
                ("app_secret", self.config.app_secret),
                ("verify_token", self.config.verify_token),
            ):
                if not v:
                    missing.append(k)
        if self._poll_enabled() and not self.config.page_id:
            missing.append("page_id")
        if not self.config.use_webhook and not self._poll_enabled():
            missing.append("use_webhook_or_poll")
        if missing:
            self.logger.error("Instagram channel missing config: {}", ", ".join(missing))
            return

        self._loop = asyncio.get_running_loop()
        self._running = True

        try:
            self._web_client = AsyncWebClient(token=self.config.slack_bot_token)
            self._socket_client = SocketModeClient(
                app_token=self.config.slack_app_token,
                web_client=self._web_client,
            )
            self._socket_client.socket_mode_request_listeners.append(
                self._on_instagram_slack_socket_request
            )
            self.logger.info("Instagram Slack Socket Mode: connecting...")
            await self._socket_client.connect()
            self._socket_task = asyncio.create_task(self._instagram_socket_keepalive())
            self.logger.info("Instagram Slack Socket Mode connected (draft approvals)")
        except Exception:
            self.logger.exception("Instagram Slack Socket Mode failed to start")
            self._running = False
            await self._shutdown_instagram_slack_socket()
            return

        if self.config.use_webhook:
            host = self.config.webhook_host
            port = int(self.config.webhook_port)
            try:
                from werkzeug.serving import make_server
            except ImportError:
                self.logger.error("werkzeug not available (install Flask)")
                await self._shutdown_instagram_slack_socket()
                self._running = False
                return

            self._httpd = make_server(host, port, self.app, threaded=True)
            self._server_thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._server_thread.start()
            self.logger.info(
                "Instagram Meta webhook listening on {}:{} (immediate inbound)",
                host,
                port,
            )

        if self._poll_enabled():
            interval = self._clamp_poll_interval(self.config.poll_interval_seconds)
            self._poll_task = asyncio.create_task(self._poll_inbound_loop(interval))
            self.logger.info("Instagram poll fallback every {}s (page_id={})", interval, self.config.page_id)
        elif not self.config.use_webhook:
            self.logger.warning(
                "Instagram poll disabled: set pageId and pollIntervalSeconds, or enable useWebhook",
            )

    async def stop(self) -> None:
        self._running = False
        if self._poll_task is not None:
            self._poll_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._poll_task
            self._poll_task = None
        await self._shutdown_instagram_slack_socket()
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
            except Exception as e:
                self.logger.warning("Instagram http shutdown: {}", e)
            self._httpd = None
        self.logger.info("Instagram channel stopped")

    async def _instagram_socket_keepalive(self) -> None:
        """Keep the asyncio task alive while Socket Mode runs its websocket loop."""
        try:
            while self._running:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            raise

    async def _shutdown_instagram_slack_socket(self) -> None:
        if self._socket_task is not None:
            self._socket_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._socket_task
            self._socket_task = None
        if self._socket_client is not None:
            try:
                await self._socket_client.close()
            except Exception as e:
                self.logger.warning("Instagram Slack socket close failed: {}", e)
            self._socket_client = None
        self._web_client = None

    async def _on_instagram_slack_socket_request(
        self,
        client: SocketModeClient,
        req: SocketModeRequest,
    ) -> None:
        """Socket Mode ingress for Slack interactive payloads (draft approvals)."""
        if req.type != "interactive":
            return
        await client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
        payload = req.payload or {}
        try:
            self._handle_slack_action(payload)
        except Exception:
            self.logger.exception("Instagram Slack interactive handler failed")

    # --- verification ---

    def _verify_meta_signature(self, req: Any) -> bool:
        sig_header = req.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            self.config.app_secret.encode(),
            req.data,
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig_header, expected):
            self.logger.warning("Meta webhook signature mismatch — rejected.")
            return False
        return True

    def _publish_inbound_sync(self, sender_id: str, text: str, raw: dict[str, Any]) -> None:
        if self._loop is None:
            self.logger.error("Event loop not set; dropping Instagram DM")
            return
        meta: dict[str, Any] = {
            "platform": "instagram",
            "raw": raw,
            "instagram_original_dm": text,
        }
        msg = InboundMessage(
            channel=self.name,
            sender_id=str(sender_id),
            chat_id=str(sender_id),
            content=f"[Instagram DM from {sender_id}]\n{text}",
            metadata=meta,
        )

        fut = asyncio.run_coroutine_threadsafe(self.bus.publish_inbound(msg), self._loop)

        def _log_err(f: asyncio.Future[Any]) -> None:
            try:
                f.result()
            except Exception:
                self.logger.exception("Failed to publish inbound Instagram message")

        fut.add_done_callback(_log_err)

    def _handle_ig_payload(self, payload: dict[str, Any]) -> None:
        for entry in payload.get("entry", []):
            for messaging in entry.get("messaging", []):
                sender_id = messaging.get("sender", {}).get("id")
                message = messaging.get("message") or {}
                text = message.get("text")
                if not text or not sender_id:
                    continue
                mid = message.get("mid") or message.get("id")
                self._ingest_inbound_dm(
                    str(sender_id),
                    str(text),
                    message_id=str(mid) if mid else None,
                    raw=messaging,
                )

    async def _poll_inbound_loop(self, interval_seconds: int) -> None:
        """Poll Meta Graph API for Instagram DMs (≤60s); dedupes with webhook delivery."""
        while self._running:
            try:
                await asyncio.to_thread(self._poll_conversations_once)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("Instagram poll error")
            try:
                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                raise

    def _poll_conversations_once(self) -> None:
        page_id = self.config.page_id
        url = f"{_GRAPH_API}/{page_id}/conversations"
        params = {
            "platform": "INSTAGRAM",
            "fields": "messages.limit(10){message,from,id,created_time}",
            "access_token": self.config.page_access_token,
        }
        with httpx.Client(timeout=30.0) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            data = response.json()

        skip_ids = {self.config.page_id, self.config.ig_user_id} - {""}
        for conv in data.get("data", []):
            messages = (conv.get("messages") or {}).get("data", [])
            for msg in messages:
                mid = msg.get("id")
                from_obj = msg.get("from") or {}
                sender_id = from_obj.get("id")
                text = msg.get("message")
                if not sender_id or not text:
                    continue
                if str(sender_id) in skip_ids:
                    continue
                self._ingest_inbound_dm(
                    str(sender_id),
                    str(text),
                    message_id=str(mid) if mid else None,
                    raw={"poll": True, "message": msg},
                )

    # --- Slack drafts ---

    def post_draft_to_slack(
        self,
        sender_id: str,
        original_message: str,
        drafted_reply: str,
        sender_display_name: str = "",
    ) -> None:
        """Post agent draft to Slack with action buttons (does not call Instagram)."""
        token = self.config.slack_bot_token
        channel = self.config.slack_draft_channel
        name_str = f" ({sender_display_name})" if sender_display_name else ""

        blocks: list[dict[str, Any]] = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        ":speech_balloon: *Instagram DM — review required*\n"
                        f"*From:* `{sender_id}`{name_str}\n"
                        f"*Customer:* {original_message}"
                    ),
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Agent draft:*\n{drafted_reply}"},
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Send"},
                        "style": "primary",
                        "action_id": ACTION_SEND,
                        "value": json.dumps({
                            "sender_id": sender_id,
                            "draft": drafted_reply,
                            "original": original_message[:300],
                        }),
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✏️ Edit & Send"},
                        "action_id": ACTION_EDIT_SEND,
                        "value": json.dumps({
                            "sender_id": sender_id,
                            "draft": drafted_reply,
                            "original": original_message[:300],
                        }),
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🗑 Discard"},
                        "style": "danger",
                        "action_id": ACTION_DISCARD,
                        "value": json.dumps({
                            "sender_id": sender_id,
                            "original": original_message[:300],
                        }),
                    },
                ],
            },
        ]

        data = self._slack_api(
            "chat.postMessage",
            {
                "channel": channel,
                "blocks": blocks,
                "text": f"Instagram DM draft for {sender_id}",
            },
            token,
        )
        if not data.get("ok"):
            self.logger.error("Slack post failed: {}", data.get("error"))
        else:
            self.logger.info("Draft posted to Slack for {}", sender_id)

    def _slack_api(self, method: str, body: dict[str, Any], token: str) -> dict[str, Any]:
        with httpx.Client(timeout=10.0) as client:
            r = client.post(
                f"https://slack.com/api/{method}",
                headers={"Authorization": f"Bearer {token}"},
                json=body,
            )
            r.raise_for_status()
            return r.json()

    def _handle_slack_action(self, payload: dict[str, Any]) -> None:
        ptype = payload.get("type")

        if ptype == "block_actions":
            user_id = (payload.get("user") or {}).get("id", "")
            for action in payload.get("actions", []):
                action_id = action.get("action_id")
                value = json.loads(action.get("value") or "{}")
                channel = payload["channel"]["id"]
                ts = payload["message"]["ts"]
                trigger_id = payload.get("trigger_id")

                if action_id == ACTION_SEND:
                    threading.Thread(
                        target=self._do_send,
                        args=(value["sender_id"], value["draft"], channel, ts, user_id),
                        daemon=True,
                    ).start()

                elif action_id == ACTION_EDIT_SEND:
                    self._open_edit_modal(
                        trigger_id=trigger_id,
                        sender_id=value["sender_id"],
                        draft=value["draft"],
                        original=value.get("original", ""),
                        slack_channel=channel,
                        slack_ts=ts,
                    )

                elif action_id == ACTION_DISCARD:
                    threading.Thread(
                        target=self._do_discard,
                        args=(value["sender_id"], value.get("original", ""), channel, ts),
                        daemon=True,
                    ).start()

        elif ptype == "view_submission":
            cb = payload.get("view", {}).get("callback_id")
            if cb == CALLBACK_EDIT_MODAL:
                self._handle_edit_modal_submit(payload)

    def _open_edit_modal(
        self,
        *,
        trigger_id: str | None,
        sender_id: str,
        draft: str,
        original: str,
        slack_channel: str,
        slack_ts: str,
    ) -> None:
        if not trigger_id:
            self.logger.error("Missing trigger_id for edit modal")
            return
        private_metadata = json.dumps({
            "sender_id": sender_id,
            "slack_channel": slack_channel,
            "slack_ts": slack_ts,
            "original": original,
        })
        modal = {
            "type": "modal",
            "callback_id": CALLBACK_EDIT_MODAL,
            "private_metadata": private_metadata,
            "title": {"type": "plain_text", "text": "Edit Instagram Reply"},
            "submit": {"type": "plain_text", "text": "Send"},
            "close": {"type": "plain_text", "text": "Cancel"},
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Customer message:*\n{original}"},
                },
                {
                    "type": "input",
                    "block_id": "edited_reply_block",
                    "label": {"type": "plain_text", "text": "Your reply"},
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "edited_reply_input",
                        "multiline": True,
                        "initial_value": draft,
                    },
                },
            ],
        }
        data = self._slack_api(
            "views.open",
            {"trigger_id": trigger_id, "view": modal},
            self.config.slack_bot_token,
        )
        if not data.get("ok"):
            self.logger.error("Failed to open edit modal: {}", data.get("error"))

    def _handle_edit_modal_submit(self, payload: dict[str, Any]) -> None:
        meta = json.loads(payload["view"]["private_metadata"])
        edited_text = (
            payload["view"]["state"]["values"]["edited_reply_block"]["edited_reply_input"]["value"]
        )
        user_id = (payload.get("user") or {}).get("id", "")
        threading.Thread(
            target=self._do_send,
            args=(
                meta["sender_id"],
                edited_text,
                meta["slack_channel"],
                meta["slack_ts"],
                user_id,
            ),
            daemon=True,
        ).start()

    def _send_instagram_message(self, recipient_id: str, text: str) -> bool:
        """Send via Meta — only from human-triggered Slack actions."""
        url = "https://graph.facebook.com/v19.0/me/messages"
        payload = {
            "recipient": {"id": recipient_id},
            "message": {"text": text},
            "messaging_type": "RESPONSE",
        }
        try:
            with httpx.Client(timeout=10.0) as client:
                r = client.post(
                    url,
                    params={"access_token": self.config.page_access_token},
                    json=payload,
                )
        except Exception:
            self.logger.exception("Instagram HTTP send failed")
            return False
        if r.status_code != 200:
            self.logger.error("Instagram send failed: {} {}", r.status_code, r.text)
            return False
        self.logger.info("Instagram message sent to {}", recipient_id)
        return True

    def _do_send(
        self,
        sender_id: str,
        text: str,
        slack_channel: str,
        slack_ts: str,
        slack_user_id: str = "",
    ) -> None:
        ok = self._send_instagram_message(sender_id, text)
        who = f"<@{slack_user_id}>" if slack_user_id else "a user"
        status = (
            f"✅ Sent to `{sender_id}` — approved by {who}"
            if ok
            else "❌ Send failed — check server logs"
        )
        self._update_slack_message(
            channel=slack_channel,
            ts=slack_ts,
            status=status,
            sent_text=text if ok else None,
        )

    def _do_discard(self, sender_id: str, _original: str, slack_channel: str, slack_ts: str) -> None:
        self._update_slack_message(
            channel=slack_channel,
            ts=slack_ts,
            status=f"🗑 Discarded — no reply sent to `{sender_id}`",
        )

    def _update_slack_message(
        self,
        *,
        channel: str,
        ts: str,
        status: str,
        sent_text: str | None = None,
    ) -> None:
        blocks: list[dict[str, Any]] = [
            {"type": "context", "elements": [{"type": "mrkdwn", "text": status}]},
        ]
        if sent_text:
            blocks.insert(0, {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Sent reply:*\n{sent_text}"},
            })
        try:
            self._slack_api(
                "chat.update",
                {"channel": channel, "ts": ts, "blocks": blocks, "text": status},
                self.config.slack_bot_token,
            )
        except Exception:
            self.logger.exception("Slack chat.update failed")
