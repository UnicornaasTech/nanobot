"""
Tool: create_gmail_draft — creates a Gmail draft (never sends).

Core logic is in create_gmail_draft(); CreateGmailDraftTool wraps it for the agent.

API reference: https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.drafts/create
Drafts guide: https://developers.google.com/workspace/gmail/api/guides/drafts
"""

from __future__ import annotations

import base64
import json
from email.mime.text import MIMEText
from typing import Any

from nanobot.agent.tools.base import Tool, tool_parameters
from nanobot.agent.tools.context import ToolContext
from nanobot.agent.tools.gmail_auth import GmailDraftToolConfig
from nanobot.agent.tools.schema import StringSchema, tool_parameters_schema


def create_gmail_draft(
    to: str,
    subject: str,
    body: str,
    thread_id: str | None = None,
    in_reply_to: str | None = None,
    references: str | None = None,
    *,
    gmail_draft_config: GmailDraftToolConfig | None = None,
) -> dict[str, Any]:
    """
    Creates a draft in Gmail. Does NOT send.

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

    msg = MIMEText(body, "plain")
    msg["To"] = to
    msg["Subject"] = subject
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode().rstrip("=")
    body_payload: dict[str, Any] = {"message": {"raw": raw}}
    if thread_id:
        body_payload["message"]["threadId"] = thread_id

    from nanobot.agent.tools.gmail_auth import get_gmail_service

    service = get_gmail_service(gmail_draft_config)
    draft = service.users().drafts().create(userId="me", body=body_payload).execute()

    draft_id = draft["id"]
    return {
        "draft_id": draft_id,
        "thread_id": draft.get("message", {}).get("threadId"),
        "gmail_url": f"https://mail.google.com/mail/u/0/#drafts/{draft_id}",
        "status": "draft_created_not_sent",
    }


@tool_parameters(
    tool_parameters_schema(
        to=StringSchema("Recipient email address"),
        subject=StringSchema("Email subject (prefix with 'Re: ' when replying)"),
        body=StringSchema("Plain-text body of the draft"),
        thread_id=StringSchema(
            "Gmail thread ID to attach the draft to (reply threading)",
            nullable=True,
        ),
        in_reply_to=StringSchema(
            "Message-ID header of the message being replied to",
            nullable=True,
        ),
        references=StringSchema(
            "References header chain for threading",
            nullable=True,
        ),
        required=["to", "subject", "body"],
    )
)
class CreateGmailDraftTool(Tool):
    """Creates a Gmail draft for human review. NEVER sends the email."""

    name = "create_gmail_draft"
    description = (
        "Creates a Gmail draft for human review. NEVER sends the email. "
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

    async def execute(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        thread_id: str | None = None,
        in_reply_to: str | None = None,
        references: str | None = None,
    ) -> str:
        try:
            result = create_gmail_draft(
                to=to,
                subject=subject,
                body=body,
                thread_id=thread_id or None,
                in_reply_to=in_reply_to or None,
                references=references or None,
                gmail_draft_config=self._gmail_draft_config,
            )
        except ValueError as e:
            return f"Error: {e}"
        except Exception as e:
            return f"Error creating Gmail draft: {e}"
        return json.dumps(result, indent=2)
