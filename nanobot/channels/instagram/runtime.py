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
import mimetypes
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx
from pydantic import Field, model_validator
from slack_sdk.socket_mode.request import SocketModeRequest
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.socket_mode.websockets import SocketModeClient
from slack_sdk.web.async_client import AsyncWebClient

from nanobot.bus.events import InboundMessage, OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.channels.base import BaseChannel
from nanobot.config.paths import get_media_dir
from nanobot.utils.document import SUPPORTED_EXTENSIONS
from nanobot.utils.helpers import detect_image_mime, safe_filename

if TYPE_CHECKING:
    from nanobot.session.manager import SessionManager
from nanobot.channels.instagram.review_state import (
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
_THREAD_CONTEXT_LIMIT = 20
_MAX_BACKFILL_IMAGES = 5
_THREAD_CONTEXT_CACHE_LIMIT = 10_000
_DOWNLOAD_TIMEOUT_S = 30.0
_MAX_ATTACHMENT_BYTES = 10_000_000
_SLACK_REVIEW_PRIOR_MESSAGES = 3
_SLACK_REVIEW_LINE_MAX_CHARS = 500
_IMAGE_ATTACHMENT_TYPES = frozenset({"image", "sticker"})
_DOCUMENT_MEDIA_EXTENSIONS = SUPPORTED_EXTENSIONS - {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
}

# Top-level channel keys removed in favor of ``accounts[]`` only.
_LEGACY_CHANNEL_CONFIG_KEYS = frozenset(
    {
        "app_secret",
        "appSecret",
        "verify_token",
        "verifyToken",
        "page_access_token",
        "pageAccessToken",
        "page_id",
        "pageId",
        "ig_user_id",
        "igUserId",
    }
)


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

    @model_validator(mode="before")
    @classmethod
    def _reject_legacy_channel_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            legacy = sorted(k for k in data if k in _LEGACY_CHANNEL_CONFIG_KEYS)
            if legacy:
                raise ValueError(
                    "channels.instagram no longer supports top-level "
                    f"{', '.join(legacy)}; move credentials into accounts[] "
                    "(see docs/prospr-custom-implementations.md)."
                )
        return data

    @model_validator(mode="after")
    def _ensure_account_keys(self) -> InstagramConfig:
        for acc in self.accounts:
            if not acc.account_key:
                acc.account_key = (acc.page_id or "account").strip() or "account"
        return self


@dataclass(frozen=True)
class _ParsedIgMessage:
    """Normalized inbound DM payload before optional thread backfill."""

    text: str
    media: list[str]
    markers: list[str]


class InstagramChannel(BaseChannel):
    """Instagram DMs in, Slack-reviewed drafts out; Meta send only from human actions."""

    name = "instagram"
    display_name = "Instagram"
    _POLL_INTERVAL_MIN = _POLL_INTERVAL_MIN
    _POLL_INTERVAL_MAX = _POLL_INTERVAL_MAX
    _MAX_SEEN_INBOUND_IDS = _MAX_SEEN_INBOUND_IDS

    def __init__(
        self,
        config: Any,
        bus: MessageBus,
        *,
        session_manager: SessionManager | None = None,
    ):
        if isinstance(config, dict):
            config = InstagramConfig.model_validate(config)
        super().__init__(config, bus)
        self.config: InstagramConfig = config
        self._session_manager = session_manager
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
        self._thread_context_attempted: set[str] = set()
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
        parsed: _ParsedIgMessage,
        *,
        message_id: str | None,
        raw: dict[str, Any],
    ) -> None:
        if not self.is_allowed(str(sender_id)):
            self.logger.warning(
                "Instagram DM from {} denied by allowFrom for account {}",
                sender_id,
                account.account_key,
            )
            return
        if message_id:
            if message_id in self._seen_inbound_ids:
                return
            self._remember_inbound_id(message_id)
        original_text = self._compose_customer_text(parsed)
        if not original_text.strip():
            return
        preview = original_text[:80] + "..." if len(original_text) > 80 else original_text
        self.logger.info(
            "Instagram DM [{}] from {}: {}",
            account.account_key,
            sender_id,
            preview,
        )
        model_text, model_media = self._maybe_thread_backfill(
            account,
            sender_id,
            original_text,
            list(parsed.media),
            exclude_message_id=message_id,
        )
        self._publish_inbound_sync(
            account,
            sender_id,
            model_text,
            raw,
            media=model_media,
            original_text=original_text,
            message_id=message_id,
        )

    @staticmethod
    def _compose_customer_text(parsed: _ParsedIgMessage) -> str:
        parts = [parsed.text] if parsed.text else []
        parts.extend(parsed.markers)
        return "\n".join(part for part in parts if part).strip()

    def _parse_inbound_message(
        self,
        message: dict[str, Any],
        account: InstagramAccountConfig,
        *,
        file_id_prefix: str,
    ) -> _ParsedIgMessage | None:
        """Extract text, local attachment paths, and markers from a Meta message."""
        text = str(message.get("text") or message.get("message") or "").strip()
        media_paths: list[str] = []
        markers: list[str] = []
        attachments = self._iter_message_attachments(message)
        for index, attachment in enumerate(attachments):
            att_type = str(attachment.get("type") or "attachment").lower()
            payload = attachment.get("payload") if isinstance(attachment.get("payload"), dict) else {}
            url = str(payload.get("url") or "")
            file_id = f"{file_id_prefix}_{index}"
            if not url:
                markers.append(f"[{att_type}: no url]")
                continue
            path = self._download_attachment_url(
                url,
                account,
                file_id=file_id,
                att_type=att_type,
            )
            if path is None:
                markers.append(f"[{att_type}: download failed]")
                continue
            path_obj = Path(path)
            label = att_type if att_type not in _IMAGE_ATTACHMENT_TYPES else "image"
            markers.append(f"[{label}: {path_obj.name} — saved to {path}]")
            if self._attachment_feeds_model_media(path_obj, att_type):
                media_paths.append(path)
        if not text and not media_paths and not markers:
            return None
        return _ParsedIgMessage(text=text, media=media_paths, markers=markers)

    @staticmethod
    def _attachment_feeds_model_media(path: Path, att_type: str) -> bool:
        """Whether a downloaded file should be passed via ``InboundMessage.media``."""
        if att_type in _IMAGE_ATTACHMENT_TYPES:
            return True
        return path.suffix.lower() in _DOCUMENT_MEDIA_EXTENSIONS

    @staticmethod
    def _iter_message_attachments(message: dict[str, Any]) -> list[dict[str, Any]]:
        attachments = message.get("attachments")
        if isinstance(attachments, list):
            return [item for item in attachments if isinstance(item, dict)]
        if isinstance(attachments, dict):
            data = attachments.get("data")
            if isinstance(data, list):
                return [item for item in data if isinstance(item, dict)]
        return []

    @staticmethod
    def _extension_for_attachment(att_type: str, content_type: str | None) -> str:
        if content_type:
            mime = content_type.split(";")[0].strip().lower()
            ext = mimetypes.guess_extension(mime)
            if ext:
                return ext
        return {
            "image": ".jpg",
            "sticker": ".webp",
            "video": ".mp4",
            "audio": ".m4a",
            "file": ".bin",
            "ig_reel": ".mp4",
            "reel": ".mp4",
        }.get(att_type, ".bin")

    def _download_attachment_url(
        self,
        url: str,
        account: InstagramAccountConfig,
        *,
        file_id: str,
        att_type: str,
    ) -> str | None:
        if not url:
            return None
        media_dir = get_media_dir("instagram")
        request_params: dict[str, str] = {}
        if account.page_access_token and "access_token=" not in url:
            request_params["access_token"] = account.page_access_token
        try:
            with httpx.Client(timeout=_DOWNLOAD_TIMEOUT_S, follow_redirects=True) as client:
                response = client.get(url, params=request_params or None)
                response.raise_for_status()
                if len(response.content) > _MAX_ATTACHMENT_BYTES:
                    self.logger.warning(
                        "Instagram attachment {} exceeds size cap ({} bytes)",
                        file_id,
                        len(response.content),
                    )
                    return None
                content_type = response.headers.get("content-type")
                if not content_type and response.content:
                    content_type = detect_image_mime(response.content)
                ext = self._extension_for_attachment(att_type, content_type)
                path = media_dir / safe_filename(f"{file_id}{ext}")
                path.write_bytes(response.content)
            return str(path)
        except Exception:
            self.logger.warning("Failed to download Instagram attachment {}", file_id)
            return None

    def _session_has_history(self, chat_id: str) -> bool:
        if self._session_manager is None:
            return False
        session_key = f"{self.name}:{chat_id}"
        session = self._session_manager.get_or_create(session_key)
        for message in session.messages:
            if message.get("role") != "user":
                continue
            content = message.get("content", "")
            if isinstance(content, str) and content.strip():
                return True
            media = message.get("media")
            if isinstance(media, list) and media:
                return True
        return False

    def _should_attempt_thread_backfill(self, chat_id: str) -> bool:
        if self._session_manager is None:
            return False
        if chat_id in self._thread_context_attempted:
            return False
        if self._session_has_history(chat_id):
            self._thread_context_attempted.add(chat_id)
            return False
        return True

    def _remember_thread_backfill_attempt(self, chat_id: str) -> None:
        if len(self._thread_context_attempted) >= _THREAD_CONTEXT_CACHE_LIMIT:
            self._thread_context_attempted.clear()
        self._thread_context_attempted.add(chat_id)

    def _maybe_thread_backfill(
        self,
        account: InstagramAccountConfig,
        sender_id: str,
        current_text: str,
        current_media: list[str],
        *,
        exclude_message_id: str | None,
    ) -> tuple[str, list[str]]:
        chat_id = compose_chat_id(account.account_key, sender_id)
        if not self._should_attempt_thread_backfill(chat_id):
            return current_text, current_media
        if not account.page_id or not account.page_access_token:
            self._remember_thread_backfill_attempt(chat_id)
            return current_text, current_media
        try:
            prior_messages = self._fetch_customer_thread_messages(account, sender_id)
        except Exception:
            self.logger.exception(
                "Instagram thread backfill failed for {}",
                chat_id,
            )
            self._remember_thread_backfill_attempt(chat_id)
            return current_text, current_media
        context_text, context_media = self._format_thread_backfill(
            account,
            prior_messages,
            exclude_message_id=exclude_message_id,
        )
        self._remember_thread_backfill_attempt(chat_id)
        if not context_text and not context_media:
            return current_text, current_media
        if context_text:
            model_text = (
                "Instagram thread context before this message:\n"
                f"{context_text}\n\nCurrent message:\n{current_text}"
            )
        else:
            model_text = current_text
        return model_text, context_media + current_media

    def _fetch_customer_thread_messages(
        self,
        account: InstagramAccountConfig,
        customer_id: str,
    ) -> list[dict[str, Any]]:
        """Fetch recent messages in the customer's DM thread via Graph API."""
        limit = _THREAD_CONTEXT_LIMIT + 1
        url = f"{_GRAPH_API}/{account.page_id}/conversations"
        params = {
            "platform": "INSTAGRAM",
            "user_id": customer_id,
            "fields": (
                f"messages.limit({limit})"
                "{message,from,id,created_time,attachments{type,payload}}"
            ),
            "access_token": account.page_access_token,
        }
        with httpx.Client(timeout=_DOWNLOAD_TIMEOUT_S) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
        if isinstance(data.get("error"), dict):
            raise RuntimeError(f"Graph API error: {data['error']}")
        for conv in data.get("data", []):
            messages = (conv.get("messages") or {}).get("data", [])
            if messages:
                return self._sort_graph_messages(messages)
        return self._fetch_customer_thread_messages_fallback(account, customer_id, limit=limit)

    def _fetch_customer_thread_messages_fallback(
        self,
        account: InstagramAccountConfig,
        customer_id: str,
        *,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Scan page conversations when user_id filter is unavailable."""
        url = f"{_GRAPH_API}/{account.page_id}/conversations"
        params = {
            "platform": "INSTAGRAM",
            "fields": (
                f"messages.limit({limit})"
                "{message,from,id,created_time,attachments{type,payload}}"
            ),
            "access_token": account.page_access_token,
        }
        with httpx.Client(timeout=_DOWNLOAD_TIMEOUT_S) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
        if isinstance(data.get("error"), dict):
            raise RuntimeError(f"Graph API error: {data['error']}")
        for conv in data.get("data", []):
            messages = (conv.get("messages") or {}).get("data", [])
            if not messages:
                continue
            senders = {
                str((msg.get("from") or {}).get("id") or "")
                for msg in messages
                if isinstance(msg, dict)
            }
            if customer_id in senders:
                return self._sort_graph_messages(messages)
        return []

    @staticmethod
    def _sort_graph_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Graph returns messages newest-first; normalize to chronological order."""
        return sorted(messages, key=lambda item: str(item.get("created_time") or ""))

    def _image_attachment_urls(self, message: dict[str, Any]) -> list[str]:
        urls: list[str] = []
        for attachment in self._iter_message_attachments(message):
            att_type = str(attachment.get("type") or "").lower()
            if att_type not in _IMAGE_ATTACHMENT_TYPES:
                continue
            payload = attachment.get("payload") if isinstance(attachment.get("payload"), dict) else {}
            url = str(payload.get("url") or "")
            if url:
                urls.append(url)
        return urls

    def _format_thread_backfill(
        self,
        account: InstagramAccountConfig,
        messages: list[dict[str, Any]],
        *,
        exclude_message_id: str | None,
    ) -> tuple[str, list[str]]:
        skip_ids = {account.page_id, account.ig_user_id} - {""}
        filtered: list[dict[str, Any]] = []
        for msg in messages:
            mid = str(msg.get("id") or "")
            if exclude_message_id and mid == exclude_message_id:
                continue
            from_obj = msg.get("from") or {}
            sender_id = str(from_obj.get("id") or "")
            if not sender_id or sender_id in skip_ids:
                continue
            filtered.append(msg)
        if len(filtered) > _THREAD_CONTEXT_LIMIT:
            filtered = filtered[-_THREAD_CONTEXT_LIMIT :]
        lines: list[str] = []
        image_jobs: list[tuple[str, str, str]] = []
        for msg in filtered:
            mid = str(msg.get("id") or "msg")
            line_text = self._graph_message_preview(msg)
            if line_text == "(no text)":
                continue
            if len(line_text) > 500:
                line_text = line_text[:500] + "…"
            lines.append(f"- customer: {line_text}")
            created = str(msg.get("created_time") or "")
            for index, url in enumerate(self._image_attachment_urls(msg)):
                image_jobs.append((created, url, f"hist_{mid}_{index}"))
        context_media: list[str] = []
        image_jobs.sort(key=lambda item: item[0])
        for _created, url, file_id in image_jobs[-_MAX_BACKFILL_IMAGES :]:
            path = self._download_attachment_url(
                url,
                account,
                file_id=file_id,
                att_type="image",
            )
            if path:
                context_media.append(path)
        return "\n".join(lines), context_media

    def _webhook_path_for_account(self, account_key: str) -> str:
        return f"{_WEBHOOK_PATH_PREFIX}{account_key}"

    def _setup_app(self) -> None:
        try:
            from flask import Flask, Response, jsonify, request
        except ImportError as e:
            self._flask_import_error = e
            return

        self.app = Flask(__name__)

        for idx, acc in enumerate(self._account_list()):
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

            # Endpoint ids are index-based so hyphen/underscore variants cannot collide.
            self.app.add_url_rule(
                path,
                endpoint=f"ig_verify_{idx}",
                view_func=make_verify_handler(acc),
                methods=["GET"],
            )
            self.app.add_url_rule(
                path,
                endpoint=f"ig_receive_{idx}",
                view_func=make_receive_handler(acc),
                methods=["POST"],
            )

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
            current_message_id=str(md.get("message_id") or "") or None,
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
        *,
        media: list[str] | None = None,
        original_text: str | None = None,
        message_id: str | None = None,
    ) -> None:
        if self._loop is None:
            self.logger.error("Event loop not set; dropping Instagram DM")
            return
        chat_id = compose_chat_id(account.account_key, sender_id)
        customer_text = original_text if original_text is not None else text
        meta: dict[str, Any] = {
            "platform": "instagram",
            "raw": raw,
            "instagram_original_dm": customer_text,
            "instagram_account_key": account.account_key,
            "instagram_account_label": account.display_label(),
            "instagram_page_id": account.page_id,
            "instagram_sender_id": sender_id,
        }
        if message_id:
            meta["message_id"] = message_id
        label = account.display_label()
        msg = InboundMessage(
            channel=self.name,
            sender_id=str(sender_id),
            chat_id=chat_id,
            content=f"[Instagram DM — {label} from {sender_id}]\n{text}",
            media=list(media or []),
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
                sender_obj = messaging.get("sender") or {}
                sender_id = sender_obj.get("id")
                if not sender_id:
                    continue
                message = messaging.get("message") or {}
                mid = message.get("mid") or message.get("id")
                file_prefix = str(mid or "webhook")
                parsed = self._parse_inbound_message(
                    message,
                    resolved,
                    file_id_prefix=file_prefix,
                )
                if parsed is None:
                    continue
                self._ingest_inbound_dm(
                    resolved,
                    str(sender_id),
                    parsed,
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
            "fields": (
                "messages.limit(10)"
                "{message,from,id,created_time,attachments{type,payload}}"
            ),
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
                if not sender_id:
                    continue
                if str(sender_id) in skip_ids:
                    continue
                file_prefix = str(mid or "poll")
                parsed = self._parse_inbound_message(
                    msg,
                    account,
                    file_id_prefix=file_prefix,
                )
                if parsed is None:
                    continue
                self._ingest_inbound_dm(
                    account,
                    str(sender_id),
                    parsed,
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

    @staticmethod
    def _truncate_slack_line(text: str, *, max_chars: int = _SLACK_REVIEW_LINE_MAX_CHARS) -> str:
        text = text.strip()
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 1].rstrip() + "…"

    def _graph_message_preview(self, message: dict[str, Any]) -> str:
        """Short customer-visible text for Slack (no attachment re-download)."""
        text = str(message.get("text") or message.get("message") or "").strip()
        parts = [text] if text else []
        for attachment in self._iter_message_attachments(message):
            att_type = str(attachment.get("type") or "attachment")
            payload = attachment.get("payload")
            if isinstance(payload, dict) and payload.get("title"):
                title = str(payload["title"]).strip()
                parts.append(f"[{att_type}: {title[:80]}]")
            else:
                parts.append(f"[{att_type}]")
        return "\n".join(parts) if parts else "(no text)"

    @staticmethod
    def _normalize_for_thread_match(text: str) -> str:
        """Compare customer text without attachment marker lines."""
        lines = [
            line
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("[")
        ]
        return "\n".join(lines).strip()

    def _build_slack_customer_thread_display(
        self,
        account: InstagramAccountConfig | None,
        customer_id: str,
        current_message: str,
        *,
        current_message_id: str | None = None,
    ) -> str:
        """Up to three prior customer messages plus the current one for Slack review."""
        current = current_message.strip()
        if account is None or not account.page_id or not account.page_access_token:
            return self._truncate_slack_line(current)
        try:
            thread_messages = self._fetch_customer_thread_messages(account, customer_id)
        except Exception:
            self.logger.warning(
                "Slack review thread context unavailable for customer {}",
                customer_id,
            )
            return self._truncate_slack_line(current)
        skip_ids = {account.page_id, account.ig_user_id} - {""}
        entries: list[tuple[str, str, str]] = []
        for msg in thread_messages:
            from_obj = msg.get("from") or {}
            sender_id = str(from_obj.get("id") or "")
            if not sender_id or sender_id in skip_ids:
                continue
            entries.append((
                str(msg.get("id") or ""),
                str(msg.get("created_time") or ""),
                self._graph_message_preview(msg),
            ))
        if not entries:
            return self._truncate_slack_line(current)
        current_index: int | None = None
        if current_message_id:
            current_index = next(
                (index for index, entry in enumerate(entries) if entry[0] == current_message_id),
                None,
            )
        if current_index is None:
            normalized_current = self._normalize_for_thread_match(current)
            if normalized_current:
                current_index = next(
                    (
                        index
                        for index, entry in enumerate(entries)
                        if self._normalize_for_thread_match(entry[2]) == normalized_current
                    ),
                    None,
                )
        if current_index is not None:
            prior_start = max(0, current_index - _SLACK_REVIEW_PRIOR_MESSAGES)
            prior = [entry[2] for entry in entries[prior_start:current_index]]
        else:
            # Current message not in Graph yet — show recent thread + explicit current.
            prior = [entry[2] for entry in entries[-_SLACK_REVIEW_PRIOR_MESSAGES :]]
        if not prior:
            return self._truncate_slack_line(current)
        lines = ["*Recent messages:*"]
        lines.extend(f"• {self._truncate_slack_line(line)}" for line in prior)
        lines.append(f"*Current message:*\n{self._truncate_slack_line(current)}")
        return "\n".join(lines)

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
        current_message_id: str | None = None,
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
        customer_text = self._build_slack_customer_thread_display(
            account,
            customer_id,
            original_message,
            current_message_id=current_message_id,
        )
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
                        f"*Customer thread:*\n{customer_text}"
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
