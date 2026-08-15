"""
Tool: create_instagram_draft — queues a Slack review draft (never sends to Instagram).

Core logic stores draft intent in ``instagram.review_state``; the Instagram channel
posts the review card when the agent turn completes.
"""

from __future__ import annotations

import json

from nanobot.agent.tools.base import Tool, tool_parameters
from nanobot.agent.tools.context import ContextAware, RequestContext, ToolContext
from nanobot.agent.tools.schema import StringSchema, tool_parameters_schema
from nanobot.channels.instagram.review_state import set_draft


@tool_parameters(
    tool_parameters_schema(
        body=StringSchema("Plain-text reply draft for human review in Slack"),
        review_notes=StringSchema(
            "Optional short notes for human reviewers (policy context, caveats, etc.)",
            nullable=True,
        ),
        required=["body"],
    )
)
class CreateInstagramDraftTool(Tool, ContextAware):
    """Queues an Instagram reply draft for Slack human review. NEVER sends to Instagram."""

    name = "create_instagram_draft"
    description = (
        "Queues an Instagram DM reply draft for human review in Slack. "
        "NEVER sends to Instagram directly. "
        "Call this when you want to propose a reply to the current Instagram customer. "
        "If no reply is needed, do not call this tool."
    )
    _scopes = {"core", "subagent"}

    def __init__(self) -> None:
        self._channel: str = ""
        self._chat_id: str = ""

    @classmethod
    def enabled(cls, ctx: ToolContext) -> bool:
        return True

    def set_context(self, ctx: RequestContext) -> None:
        self._channel = ctx.channel
        self._chat_id = ctx.chat_id

    async def execute(
        self,
        *,
        body: str,
        review_notes: str | None = None,
    ) -> str:
        if self._channel != "instagram":
            return (
                "Error: create_instagram_draft is only available for Instagram DM sessions. "
                f"Current channel is '{self._channel or 'unknown'}'."
            )

        draft_text = (body or "").strip()
        if not draft_text:
            return "Error: body must be non-empty."

        notes = (review_notes or "").strip()
        set_draft(self._chat_id, draft_text, review_notes=notes)

        return json.dumps(
            {
                "status": "instagram_draft_queued_not_sent",
                "chat_id": self._chat_id,
                "draft_length": len(draft_text),
                "has_review_notes": bool(notes),
            },
            indent=2,
        )
