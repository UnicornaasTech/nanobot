"""
Tool: create_gmail_draft — creates a Gmail draft (never sends).

Core logic is in create_gmail_draft(); CreateGmailDraftTool wraps it for the agent.

API reference: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.drafts/create
Drafts guide: https://developers.google.com/workspace/gmail/api/guides/drafts
Threading: https://developers.google.com/workspace/gmail/api/guides/threads
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from email.mime.text import MIMEText
from email.utils import parsedate_to_datetime
from typing import Any

from loguru import logger

from nanobot.agent.tools.base import Tool, tool_parameters
from nanobot.agent.tools.context import ContextAware, RequestContext, ToolContext
from nanobot.agent.tools.gmail_auth import GmailDraftToolConfig
from nanobot.agent.tools.schema import BooleanSchema, StringSchema, tool_parameters_schema


@dataclass(frozen=True)
class _OriginalMessage:
    thread_id: str
    message_id: str
    references: str
    subject: str
    from_addr: str
    date: str
    body: str


def _normalize_message_id(message_id: str) -> str:
    mid = (message_id or "").strip()
    if not mid:
        return ""
    if not mid.startswith("<"):
        mid = f"<{mid}>"
    if not mid.endswith(">"):
        mid = f"{mid}>"
    return mid


def _message_id_for_search(message_id: str) -> str:
    return _normalize_message_id(message_id).strip("<>")


def _header_value(headers: list[dict[str, str]] | None, name: str) -> str:
    if not headers:
        return ""
    target = name.lower()
    for item in headers:
        if (item.get("name") or "").lower() == target:
            return (item.get("value") or "").strip()
    return ""


def _decode_body_data(data: str) -> str:
    if not data:
        return ""
    padded = data + "=" * (-len(data) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return ""
    return raw.decode("utf-8", errors="replace")


def _extract_text_from_payload(payload: dict[str, Any] | None) -> str:
    if not payload:
        return ""
    mime_type = (payload.get("mimeType") or "").lower()
    body = payload.get("body") or {}
    data = body.get("data")
    if data and mime_type in ("text/plain", ""):
        return _decode_body_data(data).strip()
    if data and mime_type == "text/html":
        return _strip_html(_decode_body_data(data)).strip()

    parts = payload.get("parts") or []
    plain_chunks: list[str] = []
    html_chunks: list[str] = []
    for part in parts:
        part_type = (part.get("mimeType") or "").lower()
        if part_type == "text/plain":
            plain_chunks.append(_extract_text_from_payload(part))
        elif part_type == "text/html":
            html_chunks.append(_extract_text_from_payload(part))
        elif part_type.startswith("multipart/"):
            nested = _extract_text_from_payload(part)
            if nested:
                plain_chunks.append(nested)
    if plain_chunks:
        return "\n".join(chunk for chunk in plain_chunks if chunk).strip()
    if html_chunks:
        return "\n".join(chunk for chunk in html_chunks if chunk).strip()
    return ""


def _strip_html(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</p>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _format_quote_date(date_header: str) -> str:
    if not date_header:
        return ""
    try:
        dt = parsedate_to_datetime(date_header)
        return dt.strftime("%a, %b %d, %Y at %I:%M %p")
    except Exception:
        return date_header.strip()


def _quote_original_lines(body: str) -> str:
    lines = body.replace("\r\n", "\n").split("\n")
    return "\n".join(f"> {line}" if line else ">" for line in lines)


def _append_quoted_reply(reply_body: str, original: _OriginalMessage) -> str:
    reply = (reply_body or "").rstrip()
    quoted_body = _quote_original_lines(original.body or "(no message body)")
    date_label = _format_quote_date(original.date)
    author = (original.from_addr or "").strip() or "the original sender"
    attribution = (
        f"On {date_label}, {author} wrote:\n\n" if date_label else f"{author} wrote:\n\n"
    )
    quote_block = f"{attribution}{quoted_body}"
    if not reply:
        return quote_block
    return f"{reply}\n\n{quote_block}"


def _reply_subject(original_subject: str, provided_subject: str) -> str:
    original = (original_subject or "").strip()
    provided = (provided_subject or "").strip()
    if not original:
        return provided
    if not provided:
        return original if original.lower().startswith("re:") else f"Re: {original}"
    orig_base = re.sub(r"^re:\s*", "", original, flags=re.IGNORECASE).strip()
    prov_base = re.sub(r"^re:\s*", "", provided, flags=re.IGNORECASE).strip()
    if orig_base.lower() == prov_base.lower():
        return original if original.lower().startswith("re:") else f"Re: {original}"
    if provided.lower().startswith("re:"):
        return provided
    return f"Re: {original}" if not original.lower().startswith("re:") else original


def _build_references(existing_references: str, message_id: str) -> str:
    mid = _normalize_message_id(message_id)
    if not mid:
        return (existing_references or "").strip()
    refs = (existing_references or "").strip()
    if refs and mid in re.findall(r"<[^>]+>", refs):
        return refs
    if refs:
        return f"{refs} {mid}"
    return mid


def _lookup_original_message(service: Any, in_reply_to: str) -> _OriginalMessage | None:
    query_id = _message_id_for_search(in_reply_to)
    if not query_id:
        logger.warning("Gmail reply lookup skipped: empty Message-ID")
        return None
    listed = (
        service.users()
        .messages()
        .list(userId="me", q=f"rfc822msgid:{query_id}", maxResults=1)
        .execute()
    )
    hits = listed.get("messages") or []
    if not hits:
        logger.warning("Gmail reply lookup found no message for rfc822msgid:{}", query_id)
        return None
    gmail_id = hits[0]["id"]
    msg = service.users().messages().get(userId="me", id=gmail_id, format="full").execute()
    payload = msg.get("payload") or {}
    headers = payload.get("headers") or []
    message_id = _header_value(headers, "Message-ID") or _normalize_message_id(in_reply_to)
    return _OriginalMessage(
        thread_id=msg.get("threadId") or "",
        message_id=message_id,
        references=_header_value(headers, "References"),
        subject=_header_value(headers, "Subject"),
        from_addr=_header_value(headers, "From"),
        date=_header_value(headers, "Date"),
        body=_extract_text_from_payload(payload),
    )


def _original_from_fallback(
    *,
    in_reply_to: str,
    thread_id: str | None,
    references: str | None,
    subject: str | None,
    original_from: str | None,
    original_date: str | None,
    original_body: str | None,
) -> _OriginalMessage | None:
    if not (original_body or "").strip():
        return None
    return _OriginalMessage(
        thread_id=(thread_id or "").strip(),
        message_id=_normalize_message_id(in_reply_to),
        references=(references or "").strip(),
        subject=(subject or "").strip(),
        from_addr=(original_from or "").strip(),
        date=(original_date or "").strip(),
        body=(original_body or "").strip(),
    )


def _encode_mime_message(msg: MIMEText) -> str:
    return base64.urlsafe_b64encode(msg.as_bytes()).decode().rstrip("=")


def create_gmail_draft(
    to: str,
    subject: str,
    body: str,
    thread_id: str | None = None,
    in_reply_to: str | None = None,
    references: str | None = None,
    original_from: str | None = None,
    original_date: str | None = None,
    original_body: str | None = None,
    quote_original: bool = True,
    *,
    gmail_draft_config: GmailDraftToolConfig | None = None,
) -> dict[str, Any]:
    """
    Creates a draft in Gmail. Does NOT send.

    When ``in_reply_to`` (RFC Message-ID) is set, resolves the Gmail thread via API,
    sets In-Reply-To / References, matches the thread subject, and quotes the
    original message below the reply body.

    Raises:
        RuntimeError: Guard against a future ``send`` parameter on this function.
        ValueError: When ``gmail_draft_config`` is missing or incomplete.
    """
    if "send" in create_gmail_draft.__code__.co_varnames:
        raise RuntimeError("Policy violation: send parameter must never be added to this tool.")

    if gmail_draft_config is None:
        raise ValueError(
            "Gmail draft OAuth config is required. Set tools.gmailDraft in ~/.nanobot/config.json."
        )

    from nanobot.agent.tools.gmail_auth import get_gmail_service

    service = get_gmail_service(gmail_draft_config)

    original: _OriginalMessage | None = None
    if in_reply_to:
        try:
            original = _lookup_original_message(service, in_reply_to)
        except Exception as exc:
            logger.warning(
                "Gmail reply lookup failed for Message-ID {}: {}",
                in_reply_to,
                exc,
            )
            original = None
        if original is None:
            original = _original_from_fallback(
                in_reply_to=in_reply_to,
                thread_id=thread_id,
                references=references,
                subject=subject,
                original_from=original_from,
                original_date=original_date,
                original_body=original_body,
            )
            if original is not None:
                logger.warning(
                    "Gmail reply lookup using inbound metadata fallback for Message-ID {}",
                    in_reply_to,
                )
            else:
                logger.warning(
                    "Gmail reply draft for Message-ID {} will lack thread attachment and quote "
                    "(lookup miss and no original_body fallback)",
                    in_reply_to,
                )

    draft_subject = subject
    draft_body = body
    draft_thread_id = thread_id
    draft_in_reply_to = in_reply_to
    draft_references = references

    if original is not None:
        draft_subject = _reply_subject(original.subject, subject)
        draft_thread_id = draft_thread_id or original.thread_id or None
        draft_in_reply_to = original.message_id or _normalize_message_id(in_reply_to or "")
        draft_references = _build_references(
            original.references or references,
            draft_in_reply_to,
        )
        if quote_original and (original.body or original_from or original_date):
            draft_body = _append_quoted_reply(body, original)

    msg = MIMEText(draft_body, "plain")
    msg["To"] = to
    msg["Subject"] = draft_subject
    if draft_in_reply_to:
        msg["In-Reply-To"] = _normalize_message_id(draft_in_reply_to)
    if draft_references:
        msg["References"] = draft_references

    raw = _encode_mime_message(msg)
    body_payload: dict[str, Any] = {"message": {"raw": raw}}
    if draft_thread_id:
        body_payload["message"]["threadId"] = draft_thread_id

    draft = service.users().drafts().create(userId="me", body=body_payload).execute()

    draft_id = draft["id"]
    result_thread_id = draft.get("message", {}).get("threadId") or draft_thread_id
    reply_in_thread = bool(draft_thread_id and draft_in_reply_to)
    if in_reply_to and not reply_in_thread:
        logger.warning(
            "Gmail draft {} created without thread attachment (threadId={}, in_reply_to={})",
            draft_id,
            draft_thread_id or "(none)",
            draft_in_reply_to or "(none)",
        )
    gmail_url = (
        f"https://mail.google.com/mail/u/0/#inbox/{result_thread_id}"
        if result_thread_id
        else f"https://mail.google.com/mail/u/0/#drafts/{draft_id}"
    )
    return {
        "draft_id": draft_id,
        "thread_id": result_thread_id,
        "gmail_url": gmail_url,
        "status": "draft_created_not_sent",
        "reply_in_thread": reply_in_thread,
        "in_reply_to": _normalize_message_id(draft_in_reply_to) if draft_in_reply_to else None,
    }


def _format_gmail_draft_tool_result(result: dict[str, Any]) -> str:
    """Agent-facing success text (no internal draft_id — avoids noisy Slack reports)."""
    lines = ["Gmail draft created for human review (not sent)."]
    url = str(result.get("gmail_url") or "").strip()
    if url:
        lines.append(f"Open in Gmail: {url}")
    return "\n".join(lines)


@tool_parameters(
    tool_parameters_schema(
        to=StringSchema("Recipient email address"),
        subject=StringSchema(
            "Email subject; when replying, use the inbound subject (tool adds Re: if needed)"
        ),
        body=StringSchema(
            "Plain-text reply only; when in_reply_to is set the original email is quoted below"
        ),
        quote_original=BooleanSchema(
            description=(
                "When true and in_reply_to is set, append a quoted copy of the original below body"
            ),
            default=True,
            nullable=True,
        ),
        required=["to", "subject", "body"],
    )
)
class CreateGmailDraftTool(Tool, ContextAware):
    """Creates a Gmail draft for human review. NEVER sends the email."""

    name = "create_gmail_draft"
    description = (
        "Creates a Gmail draft for human review. NEVER sends the email. "
        "On email sessions, reply threading and quoted originals are applied automatically "
        "from inbound metadata — put only your reply text in body. "
        "On email sessions, your final reply is posted to channels.email.outboundSlackChannel "
        "automatically (EMAIL DRAFT header). After success, put only a brief 1-2 sentence summary "
        "in that final reply (no separate Slack heads-up; use message to Slack only for errors). "
        "Do not repeat draft IDs or raw API fields. Only separately post to channels.email.outboundSlackChannel if you encounter an error and cannot create the draft."
        "Always use this instead of any send operation. "
        "Requires tools.gmailDraft OAuth settings in config and optional dependency group [gmail]."
    )
    _scopes = {"core", "subagent"}

    config_key = "gmail_draft"

    @classmethod
    def config_cls(cls):
        return GmailDraftToolConfig

    @classmethod
    def enabled(cls, ctx: ToolContext) -> bool:
        try:
            import google.auth  # noqa: F401
            import googleapiclient  # noqa: F401
        except ImportError:
            return False
        return ctx.config.gmail_draft.is_configured()

    @classmethod
    def create(cls, ctx: ToolContext) -> Tool:
        return cls(gmail_draft_config=ctx.config.gmail_draft)

    def __init__(self, *, gmail_draft_config: GmailDraftToolConfig) -> None:
        self._gmail_draft_config = gmail_draft_config
        self._channel = ""
        self._chat_id = ""
        self._message_id: str | None = None
        self._metadata: dict[str, Any] = {}

    def set_context(self, ctx: RequestContext) -> None:
        self._channel = ctx.channel
        self._chat_id = ctx.chat_id
        self._message_id = ctx.message_id
        self._metadata = dict(ctx.metadata)

    def _email_reply_fields(self) -> dict[str, str | None]:
        """Reply threading fields derived from the active email turn (not LLM args)."""
        if self._channel != "email":
            return {}
        md = self._metadata
        message_id = (self._message_id or str(md.get("message_id") or "")).strip() or None
        if not message_id:
            logger.warning(
                "create_gmail_draft on email channel without Message-ID in request context"
            )
        sender = str(md.get("sender_email") or self._chat_id or "").strip() or None
        return {
            "in_reply_to": message_id,
            "original_from": sender,
            "original_date": str(md.get("date") or "").strip() or None,
            "original_body": str(md.get("email_body") or "").strip() or None,
            "subject_fallback": str(md.get("subject") or "").strip() or None,
        }

    async def execute(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        quote_original: bool | None = True,
    ) -> str:
        email_fields = self._email_reply_fields()
        if self._channel == "email" and not (to or "").strip():
            to = (email_fields.get("original_from") or self._chat_id or "").strip()
        effective_subject = (subject or "").strip() or (email_fields.get("subject_fallback") or "")
        try:
            result = create_gmail_draft(
                to=to,
                subject=effective_subject,
                body=body,
                in_reply_to=email_fields.get("in_reply_to"),
                original_from=email_fields.get("original_from"),
                original_date=email_fields.get("original_date"),
                original_body=email_fields.get("original_body"),
                quote_original=True if quote_original is None else bool(quote_original),
                gmail_draft_config=self._gmail_draft_config,
            )
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error creating Gmail draft: {e}"
        return _format_gmail_draft_tool_result(result)
