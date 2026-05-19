"""Delivery-target matching for unified-session mid-turn injection (fork extension).

When ``unifiedSession`` is enabled, multiple channels share ``unified:default``.
Follow-ups should only be injected into an active turn when they share the same
delivery surface (channel, chat, Slack thread); otherwise they are dispatched
as a separate turn so replies route to the correct place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nanobot.bus.events import InboundMessage

UNIFIED_SESSION_KEY = "unified:default"


@dataclass(frozen=True, slots=True)
class DeliveryTarget:
    """Outbound routing identity for a single user message."""

    channel: str
    chat_id: str
    slack_thread_ts: str | None = None


def delivery_target_from_message(msg: InboundMessage) -> DeliveryTarget:
    """Build a comparable delivery target from an inbound message."""
    chat_id = str(msg.metadata.get("context_chat_id") or msg.chat_id)
    slack_thread_ts = _slack_thread_ts(msg.channel, msg.metadata)
    return DeliveryTarget(
        channel=msg.channel,
        chat_id=chat_id,
        slack_thread_ts=slack_thread_ts,
    )


def _slack_thread_ts(channel: str, metadata: dict[str, Any] | None) -> str | None:
    if channel != "slack":
        return None
    slack = (metadata or {}).get("slack")
    if not isinstance(slack, dict):
        return None
    thread_ts = slack.get("thread_ts")
    return str(thread_ts) if thread_ts else None


def allows_unified_mid_turn_injection(
    *,
    unified_session: bool,
    session_key: str,
    inbound: InboundMessage,
    active_origin: DeliveryTarget | None,
) -> bool:
    """Return True when *inbound* may be queued on the active turn's pending queue."""
    if active_origin is None:
        return True
    if not unified_session or session_key != UNIFIED_SESSION_KEY:
        return True
    return delivery_target_from_message(inbound) == active_origin
