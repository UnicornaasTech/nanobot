"""Eager promotion of session messages into global history (fork-local)."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from loguru import logger

from nanobot.bus.events import InboundMessage

if TYPE_CHECKING:
    from nanobot.agent.memory import Consolidator
    from nanobot.config.schema import EagerKnowledgeConfig
    from nanobot.session.manager import Session, SessionManager

_EAGER_CURSOR_KEY = "_prospr_eager_cursor"
_EAGER_LAST_FLUSH_KEY = "_prospr_eager_last_flush_at"


def read_eager_cursor(session: Session) -> int:
    """Return the eager archive cursor, clamped to the current message list."""
    raw = session.metadata.get(_EAGER_CURSOR_KEY, 0)
    try:
        cursor = int(raw)
    except (TypeError, ValueError):
        cursor = 0
    return min(max(0, cursor), len(session.messages))


def eager_consolidation_start(session: Session) -> int:
    """First message index safe for token/file-cap consolidation (skip eager-archived)."""
    return max(session.last_consolidated, read_eager_cursor(session))


def adjust_eager_cursor_after_prefix_drop(session: Session, dropped: int) -> None:
    """Keep the eager cursor aligned when old messages are trimmed from the front."""
    if dropped <= 0:
        return
    session.metadata[_EAGER_CURSOR_KEY] = max(0, read_eager_cursor(session) - dropped)


def slack_provenance_from_inbound(msg: InboundMessage) -> dict[str, Any]:
    """Extract Slack thread/root linkage fields for session persistence."""
    if msg.channel != "slack":
        return {}
    slack_meta = (msg.metadata or {}).get("slack")
    if not isinstance(slack_meta, dict):
        return {}
    event = slack_meta.get("event")
    if not isinstance(event, dict):
        return {}
    ts = event.get("ts")
    thread_ts = event.get("thread_ts")
    channel_id = event.get("channel") or msg.chat_id
    if ts is None and thread_ts is None:
        return {}
    ts_s = str(ts) if ts is not None else None
    thread_s = str(thread_ts) if thread_ts is not None else None
    if thread_s:
        reply_kind = "reply"
        root_ts = thread_s
    else:
        reply_kind = "root"
        root_ts = ts_s
    return {
        "source_channel": msg.channel,
        "source_chat_id": str(channel_id),
        "slack_ts": ts_s,
        "slack_thread_ts": thread_s,
        "slack_root_ts": root_ts,
        "slack_reply_kind": reply_kind,
    }


def provenance_prefix(message: dict[str, Any]) -> str:
    """Compact prefix for archived lines (Slack thread linkage)."""
    chat = message.get("source_chat_id")
    if not chat:
        return ""
    kind = message.get("slack_reply_kind")
    ts = message.get("slack_ts")
    root = message.get("slack_root_ts")
    if kind == "reply" and root:
        return f"[slack {chat} reply root={root} ts={ts}] "
    if kind == "root" and ts:
        return f"[slack {chat} root ts={ts}] "
    return ""


def enrich_messages_for_archive(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return message copies with provenance prefixes applied to text content."""
    enriched: list[dict[str, Any]] = []
    for message in messages:
        copy = dict(message)
        prefix = provenance_prefix(message)
        content = copy.get("content")
        if prefix and isinstance(content, str) and content.strip():
            copy["content"] = f"{prefix}{content}"
        enriched.append(copy)
    return enriched


class EagerKnowledgeManager:
    """Promote session tail to history.jsonl without waiting for token overflow."""

    def __init__(
        self,
        *,
        sessions: SessionManager,
        consolidator: Consolidator,
        config: EagerKnowledgeConfig,
        schedule_background: Callable[[Awaitable[None]], None],
        get_session_lock: Callable[[str], asyncio.Lock] | None = None,
    ) -> None:
        self.sessions = sessions
        self.consolidator = consolidator
        self.config = config
        self._schedule_background = schedule_background
        self._get_session_lock = get_session_lock

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def schedule(self, session_key: str) -> None:
        """Queue a background flush attempt for *session_key*."""
        if not self.enabled:
            return
        self._schedule_background(self._run_flush(session_key, reason="scheduled"))

    async def flush_idle_singletons(self) -> None:
        """Drain sessions with sub-batch pending chunks past the idle timeout."""
        if not self.enabled:
            return
        for info in self.sessions.list_sessions():
            key = info.get("key")
            if not isinstance(key, str) or not key:
                continue
            await self._run_flush(key, reason="idle_tick")

    async def _run_flush(self, session_key: str, *, reason: str) -> None:
        session_lock = (
            self._get_session_lock(session_key)
            if self._get_session_lock is not None
            else None
        )
        if session_lock is not None:
            async with session_lock:
                await self._run_flush_under_consolidator_lock(session_key, reason=reason)
        else:
            await self._run_flush_under_consolidator_lock(session_key, reason=reason)

    async def _run_flush_under_consolidator_lock(
        self,
        session_key: str,
        *,
        reason: str,
    ) -> None:
        lock = self.consolidator.get_lock(session_key)
        async with lock:
            self.sessions.invalidate(session_key)
            await self.maybe_flush(session_key, reason=reason)

    async def maybe_flush(self, session_key: str, *, reason: str = "") -> bool:
        """Flush pending eager chunk when batch or singleton idle rules match."""
        if not self.enabled:
            return False

        session = self.sessions.get_or_create(session_key)
        cursor = read_eager_cursor(session)
        pending = session.messages[cursor:]
        if not pending:
            return False

        chunk = pending[: self.config.max_batch]
        min_batch = self.config.min_batch

        if len(chunk) >= min_batch:
            await self._flush_batch(session_key, session, cursor, chunk, reason=reason)
            return True

        if self._should_flush_singleton(chunk, reason=reason):
            self._flush_singleton_raw(session_key, session, cursor, chunk, reason=reason)
            return True

        return False

    def _advance_cursor(self, session: Session, cursor: int, flushed: int) -> None:
        new_cursor = cursor + flushed
        session.metadata[_EAGER_CURSOR_KEY] = new_cursor
        session.metadata[_EAGER_LAST_FLUSH_KEY] = datetime.now().isoformat()
        self.sessions.save(session)

    async def _flush_batch(
        self,
        session_key: str,
        session: Session,
        cursor: int,
        chunk: list[dict[str, Any]],
        *,
        reason: str,
    ) -> None:
        enriched = enrich_messages_for_archive(chunk)
        summary = await self.consolidator.archive(enriched)
        self._advance_cursor(session, cursor, len(chunk))
        if summary:
            summary_tag = "ok"
        else:
            summary_tag = "skip"
        logger.info(
            "Eager knowledge batch flush for {} ({} msgs, reason={}, summary={})",
            session_key,
            len(chunk),
            reason,
            summary_tag,
        )

    def _flush_singleton_raw(
        self,
        session_key: str,
        session: Session,
        cursor: int,
        chunk: list[dict[str, Any]],
        *,
        reason: str,
    ) -> None:
        enriched = enrich_messages_for_archive(chunk)
        formatted_text, image_blocks = self.consolidator._build_archive_payload(enriched)
        from nanobot.agent.memory import has_archivable_content

        if not has_archivable_content(formatted_text, image_blocks):
            self._advance_cursor(session, cursor, len(chunk))
            logger.debug(
                "Eager knowledge singleton skip (no archivable content) for {}",
                session_key,
            )
            return
        from nanobot.agent.memory import _RAW_ARCHIVE_MAX_CHARS
        from nanobot.utils.helpers import truncate_text
        from nanobot.utils.prompt_templates import render_template

        bootstrap = self.consolidator._load_bootstrap_context()
        system_text = render_template(
            "agent/consolidator_archive.md",
            strip=True,
            bootstrap_context=bootstrap,
        )
        truncated = self.consolidator._truncate_archive_payload(
            system_text,
            formatted_text,
            0,
        )
        body = truncated if truncated is not None else formatted_text
        for block in image_blocks:
            if block.get("type") != "image_url":
                continue
            path = (block.get("_meta") or {}).get("path", "")
            if path:
                body += f"\n[image: {path}]"
        body = truncate_text(body, _RAW_ARCHIVE_MAX_CHARS)
        if not body.strip():
            self._advance_cursor(session, cursor, len(chunk))
            logger.debug(
                "Eager knowledge singleton skip (truncated to empty) for {}",
                session_key,
            )
            return
        header = f"[single raw message {session_key}]"
        entry = f"{header}\n{body}"
        self.consolidator.store.append_history(entry, max_chars=_RAW_ARCHIVE_MAX_CHARS)
        self._advance_cursor(session, cursor, len(chunk))
        logger.info(
            "Eager knowledge singleton flush for {} ({} msgs, reason={})",
            session_key,
            len(chunk),
            reason,
        )

    def _should_flush_singleton(
        self,
        chunk: list[dict[str, Any]],
        *,
        reason: str,
    ) -> bool:
        if not chunk:
            return False
        idle_s = self.config.singleton_idle_s
        if idle_s <= 0:
            return True
        return self._idle_seconds_since(chunk) >= idle_s

    @staticmethod
    def _idle_seconds_since(chunk: list[dict[str, Any]]) -> float:
        ts = chunk[-1].get("timestamp")
        if not isinstance(ts, str):
            return 0.0
        try:
            last = datetime.fromisoformat(ts)
        except ValueError:
            return 0.0
        return max(0.0, (datetime.now() - last).total_seconds())
