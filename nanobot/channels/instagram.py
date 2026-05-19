"""
Instagram DM channel for nanobot.

Incoming DMs are published to the agent; outbound assistant text is posted to
Slack for human review (Send / Edit & Send / Discard). Only Slack button
handlers call the Instagram send API — not the agent.

Supports multiple Instagram accounts (each with its own internal Meta app
credentials). Conversation identity is namespaced per account.

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
from pydantic import Field, model_validator
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.socket_mode.websockets import SocketModeClient
from slack_sdk.web.async_client import AsyncWebClient

from nanobot.bus.events import InboundMessage, OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.channels.base import BaseChannel
from nanobot.channels.instagram_review_state import (
    clear_slack_thread_ts,
    compose_chat_id,
    consume_draft,
    get_slack_thread_ts,
    parse_chat_id,
    set_slack_thread_ts,
)
from nanobot.config.schema import Base

REVIEW_MODE_TOOL_DRAFT = "tool_draft"
REVIEW_MODE_NO_REPLY = "no_reply_suggested"

ACTION_SEND = "ig_draft_send"
ACTION_EDIT_SEND = "ig_draft_edit_send"
ACTION_DISCARD = "ig_draft_discard"
CALLBACK_EDIT_MODAL = "ig_edit_modal_submit"
_POLL_INTERVAL_MIN = 5
_POLL_INTERVAL_MAX = 60
_MAX_SEEN_INBOUND_IDS = 50_000
_GRAPH_API = "https://graph.facebook.com/v19.0"
_SLACK_ACTION_VALUE_SOFT_LIMIT = 1800
_MAX_CUSTOMER_TEXT_CHARS = 3000
_WEBHOOK_PATH_PREFIX = "/webhook/instagram/"


class InstagramAccountConfig(Base):
    """Per-account Instagram + internal Meta app credentials."""

    account_key: str = ""
    label: str = ""
    page_id: str = ""
    page_access_token: str = ""
    ig_user_id: str = ""
    app_secret: str = ""
    verify_token: str = ""

    def display_label(self) -> str:
        return (self.label or self.account_key or self.page_id or "Instagram").strip()


class InstagramConfig(Base):
    """Instagram + Slack draft-review configuration (multi-account)."""

    enabled: bool = False
    consent_granted: bool = False
    streaming: bool = False

    # Legacy single-account fields (normalized into ``accounts`` when empty).
    app_secret: str = ""
    verify_token: str = ""
    page_access_token: str = ""
    page_id: str = ""
    ig_user_id: str = ""

    accounts: list[InstagramAccountConfig] = Field(default_factory=list)

    use_webhook: bool = True
    poll_fallback_enabled: bool = True
    poll_interval_seconds: int = 60

    slack_bot_token: str = ""
    slack_draft_channel: str = ""
    slack_app_token: str = ""

    webhook_host: str = "0.0.0.0"
    webhook_port: int = 5005

    allow_from: list[str] = Field(default_factory=lambda: ["*"])

    @model_validator(mode="after")
    def _normalize_accounts(self) -> InstagramConfig:
        if not self.accounts:
            if self.page_access_token or self.page_id:
                key = (self.page_id or "default").strip() or "default"
                self.accounts = [
                    InstagramAccountConfig(
                        account_key=key,
                        label=key,
                        page_id=self.page_id,
                        page_access_token=self.page_access_token,
                        ig_user_id=self.ig_user_id,
                        app_secret=self.app_secret,
                        verify_token=self.verify_token,
                    ),
                ]
        for acc in self.accounts:
            if not acc.account_key:
                acc.account_key = (acc.page_id or "account").strip() or "account"
        return self


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
        self._accounts_by_key: dict[str, InstagramAccountConfig] = {}
        self._accounts_by_page_id: dict[str, InstagramAccountConfig] = {}
        self._build_account_indexes()
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

    def _build_account_indexes(self) -> None:
        keys: list[str] = []
        for acc in self.config.accounts:
            key = acc.account_key
            if key in self._accounts_by_key:
                raise ValueError(f"Duplicate instagram accountKey: {key!r}")
            keys.append(key)
            self._accounts_by_key[key] = acc
            if acc.page_id:
                self._accounts_by_page_id[str(acc.page_id)] = acc
        if not keys:
            return
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate instagram accountKey values in config")

    def _account_list(self) -> list[InstagramAccountConfig]:
        return list(self.config.accounts)

    def _get_account(self, account_key: str) -> InstagramAccountConfig | None:
        return self._accounts_by_key.get(account_key)

    def _resolve_account_for_webhook_entry(self, entry_id: str) -> InstagramAccountConfig | None:
        if entry_id in self._accounts_by_page_id:
            return self._accounts_by_page_id[entry_id]
        if len(self._accounts_by_key) == 1:
            return next(iter(self._accounts_by_key.values()))
        return None

    @classmethod
    def default_config(cls) -> dict[str, Any]:
        return InstagramConfig().model_dump(by_alias=True)

    @classmethod
    def _clamp_poll_interval(cls, seconds: int) -> int:
        return max(cls._POLL_INTERVAL_MIN, min(cls._POLL_INTERVAL_MAX, int(seconds)))

    def _poll_enabled(self) -> bool:
        if not any(acc.page_id for acc in self._account_list()):
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
        account: InstagramAccountConfig,
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
        self.logger.info(
            "Instagram DM [{}] from {}: {}",
            account.account_key,
            sender_id,
            preview,
        )
        self._publish_inbound_sync(account, sender_id, text, raw)

    def _webhook_path_for_account(self, account_key: str) -> str:
        return f"{_WEBHOOK_PATH_PREFIX}{account_key}"

    def _setup_app(self) -> None:
        try:
            from flask import Flask, Response, jsonify, request
        except ImportError as e:
            self._flask_import_error = e
            return

        self.app = Flask(__name__)

        for acc in self._account_list():
            path = self._webhook_path_for_account(acc.account_key)

            def make_verify_handler(account: InstagramAccountConfig):
                def ig_verify():
                    mode = request.args.get("hub.mode")
                    token = request.args.get("hub.verify_token")
                    challenge = request.args.get("hub.challenge")
                    if (
                        mode == "subscribe"
                        and token == account.verify_token
                        and challenge is not None
                    ):
                        self.logger.info(
                            "Instagram webhook verified for account {}.",
                            account.account_key,
                        )
                        return Response(str(challenge), status=200, mimetype="text/plain")
                    return Response("Forbidden", status=403, mimetype="text/plain")

                return ig_verify

            def make_receive_handler(account: InstagramAccountConfig):
                def ig_receive():
                    if not self._verify_meta_signature(request, account):
                        return "Unauthorized", 401
                    payload = request.get_json(force=True)
                    self._handle_ig_payload(payload, account)
                    return jsonify({"status": "ok"}), 200

                return ig_receive

            self.app.add_url_rule(
                path,
                endpoint=f"ig_verify_{acc.account_key}",
                view_func=make_verify_handler(acc),
                methods=["GET"],
            )
            self.app.add_url_rule(
                path,
                endpoint=f"ig_receive_{acc.account_key}",
                view_func=make_receive_handler(acc),
                methods=["POST"],
            )

        # Legacy single-route webhook when exactly one account (backward compatibility).
        if len(self._account_list()) == 1:
            sole = self._account_list()[0]

            @self.app.route("/webhook/instagram", methods=["GET"])
            def ig_verify_legacy():
                mode = request.args.get("hub.mode")
                token = request.args.get("hub.verify_token")
                challenge = request.args.get("hub.challenge")
                if mode == "subscribe" and token == sole.verify_token and challenge is not None:
                    self.logger.info("Instagram webhook verified (legacy path).")
                    return Response(str(challenge), status=200, mimetype="text/plain")
                return Response("Forbidden", status=403, mimetype="text/plain")

            @self.app.route("/webhook/instagram", methods=["POST"])
            def ig_receive_legacy():
                if not self._verify_meta_signature(request, sole):
                    return "Unauthorized", 401
                payload = request.get_json(force=True)
                self._handle_ig_payload(payload, sole)
                return jsonify({"status": "ok"}), 200

    def send_message(self, *args: Any, **kwargs: Any) -> None:
        """Spec / legacy name — direct Instagram send is never exposed to the agent."""
        raise NotImplementedError(
            "Direct Instagram send is disabled. "
            "Drafts go to Slack; humans send via the Approve button.",
        )

    async def send(self, msg: OutboundMessage) -> None:
        """Post Instagram review card to Slack (never sends to Instagram)."""
        md = msg.metadata or {}
        if md.get("_progress"):
            return
        if md.get("_turn_end") or md.get("_session_updated"):
            return
        if md.get("_stream_delta") or md.get("_stream_end"):
            return

        original = md.get("instagram_original_dm")
        if not isinstance(original, str):
            original = "(original DM not captured — check inbound metadata)"

        account_key = str(md.get("instagram_account_key") or "")
        account_label = str(md.get("instagram_account_label") or "")
        if not account_key:
            account_key, _ = parse_chat_id(msg.chat_id)
            account_key = account_key or ""
        account = self._get_account(account_key) if account_key else None
        if account and not account_label:
            account_label = account.display_label()

        draft_payload = consume_draft(msg.chat_id)
        if draft_payload is not None:
            review_mode = REVIEW_MODE_TOOL_DRAFT
            drafted_reply = draft_payload.draft_text
            review_notes = draft_payload.review_notes
            allow_send = True
        else:
            review_mode = REVIEW_MODE_NO_REPLY
            drafted_reply = ""
            review_notes = ""
            allow_send = False

        await asyncio.to_thread(
            self.post_review_to_slack,
            msg.chat_id,
            original,
            drafted_reply,
            review_mode=review_mode,
            allow_send=allow_send,
            review_notes=review_notes,
            sender_display_name=str(md.get("instagram_sender_name") or ""),
            account_key=account_key,
            account_label=account_label,
        )

    def _validate_startup_config(self) -> list[str]:
        missing: list[str] = []
        if not self.config.slack_bot_token:
            missing.append("slack_bot_token")
        if not self.config.slack_draft_channel:
            missing.append("slack_draft_channel")
        if not self.config.slack_app_token:
            missing.append("slack_app_token")
        if not self._account_list():
            missing.append("accounts")
            return missing

        if self.config.use_webhook:
            for acc in self._account_list():
                if not acc.app_secret:
                    missing.append(f"app_secret:{acc.account_key}")
                if not acc.verify_token:
                    missing.append(f"verify_token:{acc.account_key}")

        if self._poll_enabled():
            for acc in self._account_list():
                if not acc.page_id:
                    missing.append(f"page_id:{acc.account_key}")
                if not acc.page_access_token:
                    missing.append(f"page_access_token:{acc.account_key}")
        elif not self.config.use_webhook:
            missing.append("use_webhook_or_poll")

        return missing

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

        missing = self._validate_startup_config()
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
            paths = [self._webhook_path_for_account(a.account_key) for a in self._account_list()]
            self.logger.info(
                "Instagram Meta webhook listening on {}:{} paths={}",
                host,
                port,
                paths,
            )

        if self._poll_enabled():
            interval = self._clamp_poll_interval(self.config.poll_interval_seconds)
            self._poll_task = asyncio.create_task(self._poll_inbound_loop(interval))
            account_keys = [a.account_key for a in self._account_list()]
            self.logger.info(
                "Instagram poll every {}s for accounts {}",
                interval,
                account_keys,
            )
        elif not self.config.use_webhook:
            self.logger.warning(
                "Instagram poll disabled: set pageId per account and pollIntervalSeconds, "
                "or enable useWebhook",
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
        if req.type != "interactive":
            return
        await client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
        payload = req.payload or {}
        try:
            self._handle_slack_action(payload)
        except Exception:
            self.logger.exception("Instagram Slack interactive handler failed")

    def _verify_meta_signature(self, req: Any, account: InstagramAccountConfig) -> bool:
        sig_header = req.headers.get("X-Hub-Signature-256", "")
        secret = account.app_secret.encode()
        expected = "sha256=" + hmac.new(secret, req.data, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig_header, expected):
            self.logger.warning(
                "Meta webhook signature mismatch for account {} — rejected.",
                account.account_key,
            )
            return False
        return True

    def _publish_inbound_sync(
        self,
        account: InstagramAccountConfig,
        sender_id: str,
        text: str,
        raw: dict[str, Any],
    ) -> None:
        if self._loop is None:
            self.logger.error("Event loop not set; dropping Instagram DM")
            return
        chat_id = compose_chat_id(account.account_key, sender_id)
        meta: dict[str, Any] = {
            "platform": "instagram",
            "raw": raw,
            "instagram_original_dm": text,
            "instagram_account_key": account.account_key,
            "instagram_account_label": account.display_label(),
            "instagram_page_id": account.page_id,
            "instagram_sender_id": sender_id,
        }
        label = account.display_label()
        msg = InboundMessage(
            channel=self.name,
            sender_id=str(sender_id),
            chat_id=chat_id,
            content=f"[Instagram DM — {label} from {sender_id}]\n{text}",
            metadata=meta,
        )

        fut = asyncio.run_coroutine_threadsafe(self.bus.publish_inbound(msg), self._loop)

        def _log_err(f: asyncio.Future[Any]) -> None:
            try:
                f.result()
            except Exception:
                self.logger.exception("Failed to publish inbound Instagram message")

        fut.add_done_callback(_log_err)

    def _handle_ig_payload(
        self,
        payload: dict[str, Any],
        account: InstagramAccountConfig | None = None,
    ) -> None:
        for entry in payload.get("entry", []):
            entry_id = str(entry.get("id") or "")
            resolved = account or self._resolve_account_for_webhook_entry(entry_id)
            if resolved is None:
                self.logger.warning(
                    "Instagram webhook entry id {} did not match any configured account",
                    entry_id,
                )
                continue
            for messaging in entry.get("messaging", []):
                sender_id = messaging.get("sender", {}).get("id")
                message = messaging.get("message") or {}
                text = message.get("text")
                if not text or not sender_id:
                    continue
                mid = message.get("mid") or message.get("id")
                self._ingest_inbound_dm(
                    resolved,
                    str(sender_id),
                    str(text),
                    message_id=str(mid) if mid else None,
                    raw=messaging,
                )

    async def _poll_inbound_loop(self, interval_seconds: int) -> None:
        while self._running:
            try:
                await asyncio.to_thread(self._poll_all_accounts_once)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("Instagram poll error")
            try:
                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                raise

    def _poll_all_accounts_once(self) -> None:
        for account in self._account_list():
            if not account.page_id or not account.page_access_token:
                continue
            try:
                self._poll_conversations_for_account(account)
            except Exception:
                self.logger.exception(
                    "Instagram poll failed for account {}",
                    account.account_key,
                )

    def _poll_conversations_for_account(self, account: InstagramAccountConfig) -> None:
        url = f"{_GRAPH_API}/{account.page_id}/conversations"
        params = {
            "platform": "INSTAGRAM",
            "fields": "messages.limit(10){message,from,id,created_time}",
            "access_token": account.page_access_token,
        }
        with httpx.Client(timeout=30.0) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            data = response.json()

        skip_ids = {account.page_id, account.ig_user_id} - {""}
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
                    account,
                    str(sender_id),
                    str(text),
                    message_id=str(mid) if mid else None,
                    raw={"poll": True, "account_key": account.account_key, "message": msg},
                )

    def _slack_action_base(
        self,
        *,
        account_key: str,
        sender_id: str,
        draft: str = "",
        original: str = "",
    ) -> dict[str, Any]:
        return {
            "account_key": account_key,
            "sender_id": sender_id,
            "draft": draft,
            "original": original[:300],
        }

    def post_draft_to_slack(
        self,
        chat_id: str,
        original_message: str,
        drafted_reply: str,
        sender_display_name: str = "",
        *,
        account_key: str = "",
        account_label: str = "",
    ) -> None:
        """Backward-compatible wrapper for tool-draft review cards."""
        self.post_review_to_slack(
            chat_id,
            original_message,
            drafted_reply,
            review_mode=REVIEW_MODE_TOOL_DRAFT,
            allow_send=True,
            sender_display_name=sender_display_name,
            account_key=account_key,
            account_label=account_label,
        )

    def post_review_to_slack(
        self,
        chat_id: str,
        original_message: str,
        drafted_reply: str,
        *,
        review_mode: str = REVIEW_MODE_TOOL_DRAFT,
        allow_send: bool = True,
        review_notes: str = "",
        sender_display_name: str = "",
        account_key: str = "",
        account_label: str = "",
    ) -> None:
        """Post an Instagram review card to Slack (does not call Instagram)."""
        parsed_key, customer_id = parse_chat_id(chat_id)
        if not account_key and parsed_key:
            account_key = parsed_key
        if not account_key and len(self._account_list()) == 1:
            account_key = self._account_list()[0].account_key
        account = self._get_account(account_key) if account_key else None
        if account and not account_label:
            account_label = account.display_label()
        account_line = ""
        if account_label or account_key:
            account_line = f"*Account:* {account_label or account_key}"
            if account_key and account_label and account_key != account_label:
                account_line += f" (`{account_key}`)"
            account_line += "\n"

        token = self.config.slack_bot_token
        channel = self.config.slack_draft_channel
        name_str = f" ({sender_display_name})" if sender_display_name else ""
        is_tool_draft = review_mode == REVIEW_MODE_TOOL_DRAFT

        header = (
            ":speech_balloon: *Instagram DM — review required*"
            if is_tool_draft
            else ":speech_balloon: *Instagram DM — no reply suggested*"
        )
        customer_text = original_message
        if len(customer_text) > _MAX_CUSTOMER_TEXT_CHARS:
            customer_text = customer_text[:_MAX_CUSTOMER_TEXT_CHARS] + "\n…(truncated)"

        blocks: list[dict[str, Any]] = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{header}\n"
                        f"{account_line}"
                        f"*From:* `{customer_id}`{name_str}\n"
                        f"*Customer message:*\n{customer_text}"
                    ),
                },
            },
            {"type": "divider"},
        ]

        if is_tool_draft:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Agent draft:*\n{drafted_reply}"},
            })
            if review_notes:
                blocks.append({
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"*Reviewer notes:* {review_notes}"}],
                })
        else:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        "*Agent assessment:* The agent did not propose a reply for this message. "
                        "Use *Edit & Send* if you still want to respond."
                    ),
                },
            })

        action_elements: list[dict[str, Any]] = []
        send_value = self._slack_action_base(
            account_key=account_key,
            sender_id=customer_id,
            draft=drafted_reply,
            original=original_message,
        )
        send_allowed = allow_send
        if allow_send and len(json.dumps(send_value)) > _SLACK_ACTION_VALUE_SOFT_LIMIT:
            send_allowed = False
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": (
                        "Send button disabled because the draft is too long for "
                        "Slack action payload limits; use *Edit & Send*."
                    ),
                }],
            })

        if send_allowed:
            action_elements.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "✅ Send"},
                "style": "primary",
                "action_id": ACTION_SEND,
                "value": json.dumps(send_value),
            })
        edit_value = self._slack_action_base(
            account_key=account_key,
            sender_id=customer_id,
            draft=drafted_reply,
            original=original_message,
        )
        discard_value = self._slack_action_base(
            account_key=account_key,
            sender_id=customer_id,
            original=original_message,
        )
        action_elements.extend([
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "✏️ Edit & Send"},
                "action_id": ACTION_EDIT_SEND,
                "value": json.dumps(edit_value),
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "🗑 Discard"},
                "style": "danger",
                "action_id": ACTION_DISCARD,
                "value": json.dumps(discard_value),
            },
        ])
        blocks.append({"type": "actions", "elements": action_elements})

        fallback = (
            f"Instagram DM draft for {customer_id}"
            if is_tool_draft
            else f"Instagram DM — no reply suggested for {customer_id}"
        )
        self._post_slack_review_message(
            chat_id=chat_id,
            customer_id=customer_id,
            channel=channel,
            token=token,
            blocks=blocks,
            fallback_text=fallback,
            sender_display_name=sender_display_name,
            account_key=account_key,
            account_label=account_label or account_key,
        )

    def _ensure_slack_thread(
        self,
        chat_id: str,
        *,
        customer_id: str,
        sender_display_name: str = "",
        account_key: str = "",
        account_label: str = "",
    ) -> str | None:
        existing = get_slack_thread_ts(chat_id)
        if existing:
            return existing

        channel = self.config.slack_draft_channel
        token = self.config.slack_bot_token
        name_str = f" ({sender_display_name})" if sender_display_name else ""
        acct = f" — {account_label}" if account_label else ""
        body = {
            "channel": channel,
            "text": f"Instagram conversation with {customer_id}{acct}",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            ":instagram: *Instagram conversation*\n"
                            f"*Account:* {account_label or account_key or '—'}\n"
                            f"*Customer:* `{customer_id}`{name_str}"
                        ),
                    },
                },
            ],
        }
        data = self._slack_api("chat.postMessage", body, token)
        if not data.get("ok"):
            self.logger.error(
                "Failed to create Slack thread anchor for {}: {}",
                chat_id,
                data.get("error"),
            )
            return None

        thread_ts = str(data.get("ts") or "")
        if not thread_ts:
            self.logger.error("Slack thread anchor for {} returned no ts", chat_id)
            return None

        set_slack_thread_ts(chat_id, thread_ts)
        self.logger.info("Created Slack thread anchor for {}", chat_id)
        return thread_ts

    def _post_slack_review_message(
        self,
        *,
        chat_id: str,
        customer_id: str,
        channel: str,
        token: str,
        blocks: list[dict[str, Any]],
        fallback_text: str,
        sender_display_name: str = "",
        account_key: str = "",
        account_label: str = "",
    ) -> None:
        thread_ts = self._ensure_slack_thread(
            chat_id,
            customer_id=customer_id,
            sender_display_name=sender_display_name,
            account_key=account_key,
            account_label=account_label,
        )
        body: dict[str, Any] = {
            "channel": channel,
            "blocks": blocks,
            "text": fallback_text,
        }
        if thread_ts:
            body["thread_ts"] = thread_ts

        data = self._slack_api("chat.postMessage", body, token)
        if data.get("ok"):
            self.logger.info("Review posted to Slack for {}", chat_id)
            return

        error = data.get("error", "")
        if thread_ts and error in {"thread_not_found", "message_not_found", "invalid_thread_ts"}:
            self.logger.warning(
                "Slack thread anchor missing for {} ({}), creating a new one",
                chat_id,
                error,
            )
            clear_slack_thread_ts(chat_id)
            new_thread = self._ensure_slack_thread(
                chat_id,
                customer_id=customer_id,
                sender_display_name=sender_display_name,
                account_key=account_key,
                account_label=account_label,
            )
            if new_thread:
                body["thread_ts"] = new_thread
                data = self._slack_api("chat.postMessage", body, token)

        if not data.get("ok"):
            self.logger.error("Slack post failed for {}: {}", chat_id, data.get("error"))
        else:
            self.logger.info("Review posted to Slack for {}", chat_id)

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
                account_key = value.get("account_key", "")
                sender_id = value["sender_id"]

                if action_id == ACTION_SEND:
                    threading.Thread(
                        target=self._do_send,
                        args=(account_key, sender_id, value["draft"], channel, ts, user_id),
                        daemon=True,
                    ).start()

                elif action_id == ACTION_EDIT_SEND:
                    self._open_edit_modal(
                        trigger_id=trigger_id,
                        account_key=account_key,
                        sender_id=sender_id,
                        draft=value["draft"],
                        original=value.get("original", ""),
                        slack_channel=channel,
                        slack_ts=ts,
                    )

                elif action_id == ACTION_DISCARD:
                    threading.Thread(
                        target=self._do_discard,
                        args=(account_key, sender_id, value.get("original", ""), channel, ts),
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
        account_key: str,
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
            "account_key": account_key,
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
                meta.get("account_key", ""),
                meta["sender_id"],
                edited_text,
                meta["slack_channel"],
                meta["slack_ts"],
                user_id,
            ),
            daemon=True,
        ).start()

    def _send_instagram_message(
        self,
        recipient_id: str,
        text: str,
        account_key: str,
    ) -> bool:
        """Send via Meta — only from human-triggered Slack actions."""
        account = self._get_account(account_key)
        if account is None and len(self._account_list()) == 1:
            account = self._account_list()[0]
        if account is None:
            self.logger.error("Instagram send: unknown account_key {}", account_key)
            return False
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
                    params={"access_token": account.page_access_token},
                    json=payload,
                )
        except Exception:
            self.logger.exception("Instagram HTTP send failed")
            return False
        if r.status_code != 200:
            self.logger.error(
                "Instagram send failed [{}]: {} {}",
                account.account_key,
                r.status_code,
                r.text,
            )
            return False
        self.logger.info(
            "Instagram message sent to {} via account {}",
            recipient_id,
            account.account_key,
        )
        return True

    def _do_send(
        self,
        account_key: str,
        sender_id: str,
        text: str,
        slack_channel: str,
        slack_ts: str,
        slack_user_id: str = "",
    ) -> None:
        ok = self._send_instagram_message(sender_id, text, account_key)
        who = f"<@{slack_user_id}>" if slack_user_id else "a user"
        acct = f" [{account_key}]" if account_key else ""
        status = (
            f"✅ Sent to `{sender_id}`{acct} — approved by {who}"
            if ok
            else "❌ Send failed — check server logs"
        )
        self._update_slack_message(
            channel=slack_channel,
            ts=slack_ts,
            status=status,
            sent_text=text if ok else None,
        )

    def _do_discard(
        self,
        account_key: str,
        sender_id: str,
        _original: str,
        slack_channel: str,
        slack_ts: str,
    ) -> None:
        acct = f" [{account_key}]" if account_key else ""
        self._update_slack_message(
            channel=slack_channel,
            ts=slack_ts,
            status=f"🗑 Discarded — no reply sent to `{sender_id}`{acct}",
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
