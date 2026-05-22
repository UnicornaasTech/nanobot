"""Memory system: pure file I/O store, lightweight Consolidator, and Dream processor."""

from __future__ import annotations

import asyncio
import json
import mimetypes
import os
import re
import weakref
from contextlib import suppress
from datetime import datetime
from importlib.resources import files as pkg_files
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterator

import tiktoken
from loguru import logger

from nanobot.agent.eager_knowledge import eager_consolidation_start
from nanobot.agent.runner import AgentRunner, AgentRunSpec
from nanobot.agent.tools.registry import ToolRegistry
from nanobot.session.manager import Session
from nanobot.utils.document import extract_documents
from nanobot.utils.gitstore import GitStore
from nanobot.utils.helpers import (
    build_image_content_blocks,
    detect_image_mime,
    ensure_dir,
    estimate_message_tokens,
    estimate_prompt_tokens_chain,
    find_legal_message_start,
    strip_think,
    truncate_text,
)
from nanobot.utils.prompt_templates import render_template

if TYPE_CHECKING:
    from nanobot.providers.base import LLMProvider
    from nanobot.session.manager import SessionManager


# ---------------------------------------------------------------------------
# MemoryStore — pure file I/O layer
# ---------------------------------------------------------------------------

class MemoryStore:
    """Pure file I/O for memory files: MEMORY.md, history.jsonl, SOUL.md, USER.md."""

    _DEFAULT_MAX_HISTORY = 1000
    _LEGACY_ENTRY_START_RE = re.compile(r"^\[(\d{4}-\d{2}-\d{2}[^\]]*)\]\s*")
    _LEGACY_TIMESTAMP_RE = re.compile(r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\]\s*")
    _LEGACY_RAW_MESSAGE_RE = re.compile(
        r"^\[\d{4}-\d{2}-\d{2}[^\]]*\]\s+[A-Z][A-Z0-9_]*(?:\s+\[tools:\s*[^\]]+\])?:"
    )

    def __init__(self, workspace: Path, max_history_entries: int = _DEFAULT_MAX_HISTORY):
        self.workspace = workspace
        self.max_history_entries = max_history_entries
        self.memory_dir = ensure_dir(workspace / "memory")
        self.memory_file = self.memory_dir / "MEMORY.md"
        self.history_file = self.memory_dir / "history.jsonl"
        self.legacy_history_file = self.memory_dir / "HISTORY.md"
        self.soul_file = workspace / "SOUL.md"
        self.user_file = workspace / "USER.md"
        self._cursor_file = self.memory_dir / ".cursor"
        self._dream_cursor_file = self.memory_dir / ".dream_cursor"
        self._corruption_logged = False  # rate-limit non-int cursor warning
        self._oversize_logged = False  # rate-limit oversized-entry warning
        self._git = GitStore(workspace, tracked_files=[
            "SOUL.md", "USER.md", "memory/MEMORY.md", "memory/.dream_cursor",
        ])
        self._maybe_migrate_legacy_history()

    @property
    def git(self) -> GitStore:
        return self._git

    # -- generic helpers -----------------------------------------------------

    @staticmethod
    def read_file(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return ""

    def _maybe_migrate_legacy_history(self) -> None:
        """One-time upgrade from legacy HISTORY.md to history.jsonl.

        The migration is best-effort and prioritizes preserving as much content
        as possible over perfect parsing.
        """
        if not self.legacy_history_file.exists():
            return
        if self.history_file.exists() and self.history_file.stat().st_size > 0:
            return

        try:
            legacy_text = self.legacy_history_file.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            logger.exception("Failed to read legacy HISTORY.md for migration")
            return

        entries = self._parse_legacy_history(legacy_text)
        try:
            if entries:
                self._write_entries(entries)
                last_cursor = entries[-1]["cursor"]
                self._cursor_file.write_text(str(last_cursor), encoding="utf-8")
                # Default to "already processed" so upgrades do not replay the
                # user's entire historical archive into Dream on first start.
                self._dream_cursor_file.write_text(str(last_cursor), encoding="utf-8")

            backup_path = self._next_legacy_backup_path()
            self.legacy_history_file.replace(backup_path)
            logger.info(
                "Migrated legacy HISTORY.md to history.jsonl ({} entries)",
                len(entries),
            )
        except Exception:
            logger.exception("Failed to migrate legacy HISTORY.md")

    def _parse_legacy_history(self, text: str) -> list[dict[str, Any]]:
        normalized = text.replace("\r\n", "\n").replace("\r", "\n").strip()
        if not normalized:
            return []

        fallback_timestamp = self._legacy_fallback_timestamp()
        entries: list[dict[str, Any]] = []
        chunks = self._split_legacy_history_chunks(normalized)

        for cursor, chunk in enumerate(chunks, start=1):
            timestamp = fallback_timestamp
            content = chunk
            match = self._LEGACY_TIMESTAMP_RE.match(chunk)
            if match:
                timestamp = match.group(1)
                remainder = chunk[match.end():].lstrip()
                if remainder:
                    content = remainder

            entries.append({
                "cursor": cursor,
                "timestamp": timestamp,
                "content": content,
            })
        return entries

    def _split_legacy_history_chunks(self, text: str) -> list[str]:
        lines = text.split("\n")
        chunks: list[str] = []
        current: list[str] = []
        saw_blank_separator = False

        for line in lines:
            if saw_blank_separator and line.strip() and current:
                chunks.append("\n".join(current).strip())
                current = [line]
                saw_blank_separator = False
                continue
            if self._should_start_new_legacy_chunk(line, current):
                chunks.append("\n".join(current).strip())
                current = [line]
                saw_blank_separator = False
                continue
            current.append(line)
            saw_blank_separator = not line.strip()

        if current:
            chunks.append("\n".join(current).strip())
        return [chunk for chunk in chunks if chunk]

    def _should_start_new_legacy_chunk(self, line: str, current: list[str]) -> bool:
        if not current:
            return False
        if not self._LEGACY_ENTRY_START_RE.match(line):
            return False
        if self._is_raw_legacy_chunk(current) and self._LEGACY_RAW_MESSAGE_RE.match(line):
            return False
        return True

    def _is_raw_legacy_chunk(self, lines: list[str]) -> bool:
        first_nonempty = next((line for line in lines if line.strip()), "")
        match = self._LEGACY_TIMESTAMP_RE.match(first_nonempty)
        if not match:
            return False
        return first_nonempty[match.end():].lstrip().startswith("[RAW]")

    def _legacy_fallback_timestamp(self) -> str:
        try:
            return datetime.fromtimestamp(
                self.legacy_history_file.stat().st_mtime,
            ).strftime("%Y-%m-%d %H:%M")
        except OSError:
            return datetime.now().strftime("%Y-%m-%d %H:%M")

    def _next_legacy_backup_path(self) -> Path:
        candidate = self.memory_dir / "HISTORY.md.bak"
        suffix = 2
        while candidate.exists():
            candidate = self.memory_dir / f"HISTORY.md.bak.{suffix}"
            suffix += 1
        return candidate

    # -- MEMORY.md (long-term facts) -----------------------------------------

    def read_memory(self) -> str:
        return self.read_file(self.memory_file)

    def write_memory(self, content: str) -> None:
        self.memory_file.write_text(content, encoding="utf-8")

    # -- SOUL.md -------------------------------------------------------------

    def read_soul(self) -> str:
        return self.read_file(self.soul_file)

    def write_soul(self, content: str) -> None:
        self.soul_file.write_text(content, encoding="utf-8")

    # -- USER.md -------------------------------------------------------------

    def read_user(self) -> str:
        return self.read_file(self.user_file)

    def write_user(self, content: str) -> None:
        self.user_file.write_text(content, encoding="utf-8")

    # -- context injection (used by context.py) ------------------------------

    def get_memory_context(self) -> str:
        long_term = self.read_memory()
        return f"## Long-term Memory\n{long_term}" if long_term else ""

    # -- history.jsonl — append-only, JSONL format ---------------------------

    def append_history(self, entry: str, *, max_chars: int | None = None) -> int:
        """Append *entry* to history.jsonl and return its auto-incrementing cursor.

        Entries are passed through `strip_think` to drop template-level leaks
        (e.g. unclosed `<think` prefixes, `<channel|>` markers) before being
        persisted. If the cleaned content is empty but the raw entry wasn't,
        the record is persisted with an empty string rather than falling back
        to the raw leak — otherwise `strip_think`'s guarantees would be
        undone by history replay / consolidation downstream.

        A defensive cap (*max_chars*, default ``_HISTORY_ENTRY_HARD_CAP``) is
        applied as a final safety net: individual callers should cap their own
        content more tightly; this default only exists to catch unintentional
        large writes (e.g. an LLM echoing its input back as a "summary").
        """
        limit = max_chars if max_chars is not None else _HISTORY_ENTRY_HARD_CAP
        cursor = self._next_cursor()
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        raw = entry.rstrip()
        if len(raw) > limit:
            if not self._oversize_logged:
                self._oversize_logged = True
                logger.warning(
                    "history entry exceeds {} chars ({}); truncating. "
                    "Usually means a caller forgot its own cap; "
                    "further occurrences suppressed.",
                    limit, len(raw),
                )
            raw = truncate_text(raw, limit)
        content = strip_think(raw)
        if raw and not content:
            logger.debug(
                "history entry {} stripped to empty (likely template leak); "
                "persisting empty content to avoid re-polluting context",
                cursor,
            )
        record = {"cursor": cursor, "timestamp": ts, "content": content}
        with open(self.history_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        self._cursor_file.write_text(str(cursor), encoding="utf-8")
        return cursor

    @staticmethod
    def _valid_cursor(value: Any) -> int | None:
        """Int cursors only — reject bool (``isinstance(True, int)`` is True)."""
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value

    def _iter_valid_entries(self) -> Iterator[tuple[dict[str, Any], int]]:
        """Yield ``(entry, cursor)`` for entries with int cursors; warn once on corruption."""
        poisoned: Any = None
        for entry in self._read_entries():
            raw = entry.get("cursor")
            if raw is None:
                continue
            cursor = self._valid_cursor(raw)
            if cursor is None:
                poisoned = raw
                continue
            yield entry, cursor
        if poisoned is not None and not self._corruption_logged:
            self._corruption_logged = True
            logger.warning(
                "history.jsonl contains a non-int cursor ({!r}); dropping it. "
                "Usually caused by an external writer; further occurrences suppressed.",
                poisoned,
            )

    def _next_cursor(self) -> int:
        """Read the current cursor counter and return the next value."""
        if self._cursor_file.exists():
            with suppress(ValueError, OSError):
                return int(self._cursor_file.read_text(encoding="utf-8").strip()) + 1
        # Fast path: trust the tail when intact.  Otherwise scan the whole
        # file and take ``max`` — that stays correct even if the monotonic
        # invariant was broken by external writes.
        last = self._read_last_entry() or {}
        cursor = self._valid_cursor(last.get("cursor"))
        if cursor is not None:
            return cursor + 1
        return max((c for _, c in self._iter_valid_entries()), default=0) + 1

    def read_unprocessed_history(self, since_cursor: int) -> list[dict[str, Any]]:
        """Return history entries with a valid cursor > *since_cursor*."""
        return [e for e, c in self._iter_valid_entries() if c > since_cursor]

    def compact_history(self) -> None:
        """Drop oldest entries if the file exceeds *max_history_entries*."""
        if self.max_history_entries <= 0:
            return
        entries = self._read_entries()
        if len(entries) <= self.max_history_entries:
            return
        kept = entries[-self.max_history_entries:]
        self._write_entries(kept)

    # -- JSONL helpers -------------------------------------------------------

    def _read_entries(self) -> list[dict[str, Any]]:
        """Read all entries from history.jsonl."""
        entries: list[dict[str, Any]] = []
        with suppress(FileNotFoundError):
            with open(self.history_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        return entries

    def _read_last_entry(self) -> dict[str, Any] | None:
        """Read the last entry from the JSONL file efficiently."""
        try:
            with open(self.history_file, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return None
                read_size = min(size, 4096)
                f.seek(size - read_size)
                data = f.read().decode("utf-8")
                lines = [line for line in data.split("\n") if line.strip()]
                if not lines:
                    return None
                return json.loads(lines[-1])
        except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _write_entries(self, entries: list[dict[str, Any]]) -> None:
        """Overwrite history.jsonl with the given entries (atomic write)."""
        tmp_path = self.history_file.with_suffix(self.history_file.suffix + ".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                for entry in entries:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.history_file)

            # fsync the directory so the rename is durable.
            # On Windows, opening a directory with O_RDONLY raises
            # PermissionError — skip the dir sync there (NTFS
            # journals metadata synchronously).
            with suppress(PermissionError):
                fd = os.open(str(self.history_file.parent), os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    # -- dream cursor --------------------------------------------------------

    def get_last_dream_cursor(self) -> int:
        if self._dream_cursor_file.exists():
            with suppress(ValueError, OSError):
                return int(self._dream_cursor_file.read_text(encoding="utf-8").strip())
        return 0

    def set_last_dream_cursor(self, cursor: int) -> None:
        self._dream_cursor_file.write_text(str(cursor), encoding="utf-8")

    # -- message formatting utility ------------------------------------------

    @staticmethod
    def _format_messages(messages: list[dict]) -> str:
        lines = []
        for message in messages:
            if not message.get("content"):
                continue
            tools = f" [tools: {', '.join(message['tools_used'])}]" if message.get("tools_used") else ""
            lines.append(
                f"[{message.get('timestamp', '?')[:16]}] {message['role'].upper()}{tools}: {message['content']}"
            )
        return "\n".join(lines)

    def raw_archive(self, messages: list[dict], *, max_chars: int | None = None) -> None:
        """Fallback: dump raw messages to history.jsonl without LLM summarization."""
        limit = max_chars if max_chars is not None else _RAW_ARCHIVE_MAX_CHARS
        formatted = truncate_text(self._format_messages(messages), limit)
        self.append_history(
            f"[RAW] {len(messages)} messages\n"
            f"{formatted}"
        )
        logger.warning(
            "Memory consolidation degraded: raw-archived {} messages", len(messages)
        )


# ---------------------------------------------------------------------------
# Archive formatting and summary normalization
# ---------------------------------------------------------------------------

_ARCHIVE_BOOTSTRAP_FILES = ("AGENTS.md", "SOUL.md", "USER.md", "TOOLS.md")
_ARCHIVE_TRANSCRIPT_HEADER = "## INPUT — Conversation transcript (summarize THIS only)\n\n"
_NOOP_SUMMARIES = frozenset({"(nothing)", "[no summary]"})
ARCHIVE_IMAGE_TOKEN_RESERVE = 1200
ARCHIVE_SYSTEM_OVERHEAD = 512


def _normalize_archive_summary(text: str | None) -> str | None:
    """Return None for empty or no-op consolidation outputs."""
    if not text or not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped:
        return None
    if stripped.lower() in _NOOP_SUMMARIES:
        return None
    return stripped


def _is_workspace_template_content(content: str, template_path: str) -> bool:
    """True when workspace file is still the bundled default template."""
    with suppress(Exception):
        tpl = pkg_files("nanobot") / "templates" / template_path
        if tpl.is_file():
            return content.strip() == tpl.read_text(encoding="utf-8").strip()
    return False


def _estimate_text_tokens(text: str) -> int:
    try:
        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        return max(1, len(text) // 4)


def _content_to_archive_text(content: Any) -> str:
    """Normalize session message content to plain text for archive formatting."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str) and text.strip():
                    parts.append(text)
        return "\n".join(parts)
    if content is None:
        return ""
    return str(content)


def _format_tools_suffix(message: dict[str, Any]) -> str:
    tools_used = message.get("tools_used")
    if not tools_used or not isinstance(tools_used, (list, tuple)):
        return ""
    names = [str(t) for t in tools_used if t]
    return f" [tools: {', '.join(names)}]" if names else ""


def _count_archive_vision_images(image_blocks: list[dict[str, Any]]) -> int:
    return sum(
        1 for block in image_blocks if isinstance(block, dict) and block.get("type") == "image_url"
    )


def _format_message_line(message: dict[str, Any]) -> str | None:
    """Single transcript line from message content (no media expansion)."""
    content = _content_to_archive_text(message.get("content"))
    if not content.strip():
        return None
    tools = _format_tools_suffix(message)
    return (
        f"[{message.get('timestamp', '?')[:16]}] "
        f"{message.get('role', 'user').upper()}{tools}: {content}"
    )


def format_messages_for_archive(
    messages: list[dict[str, Any]],
    *,
    max_media_bytes: int,
    extract_max_chars: int,
    max_images: int,
) -> tuple[str, list[dict[str, Any]]]:
    """Build transcript text and optional vision blocks for consolidation."""
    lines: list[str] = []
    image_blocks: list[dict[str, Any]] = []
    images_embedded = 0

    for message in messages:
        text = _content_to_archive_text(message.get("content"))
        media_paths = message.get("media")
        paths: list[str] = []
        if isinstance(media_paths, list):
            paths = [p for p in media_paths if isinstance(p, str) and p]

        doc_parts: list[str] = []
        for path_str in paths:
            p = Path(path_str)
            if not p.is_file():
                lines.append(f"[media missing: {p.name}]")
                continue
            try:
                size = p.stat().st_size
            except OSError:
                lines.append(f"[media unreadable: {p.name}]")
                continue
            if size > max_media_bytes:
                lines.append(
                    f"[media skipped: {p.name} ({size} bytes > {max_media_bytes} limit)]"
                )
                continue

            with open(p, "rb") as f:
                header = f.read(16)
            mime = detect_image_mime(header) or mimetypes.guess_type(path_str)[0]
            if mime and mime.startswith("image/"):
                if images_embedded >= max_images:
                    lines.append(f"[image skipped: batch image limit ({max_images})]")
                    continue
                try:
                    raw = p.read_bytes()
                except OSError:
                    lines.append(f"[image unreadable: {p.name}]")
                    continue
                if len(raw) > max_media_bytes:
                    lines.append(f"[media skipped: {p.name} ({len(raw)} bytes > limit)]")
                    continue
                img_mime = detect_image_mime(raw) or mime
                image_blocks.extend(
                    build_image_content_blocks(
                        raw,
                        img_mime,
                        str(p.resolve()),
                        f"(archive image: {p.name})",
                    )
                )
                images_embedded += 1
                continue

            extracted, _images = extract_documents(
                "",
                [path_str],
                max_file_size=max_media_bytes,
            )
            if extracted and extracted.strip():
                body = extracted.strip()
                if len(body) > extract_max_chars:
                    body = truncate_text(body, extract_max_chars) + " … (truncated for archive)"
                doc_parts.append(body)

        line = _format_message_line(message)
        combined = text.strip()
        if doc_parts:
            combined = "\n\n".join(part for part in [combined, *doc_parts] if part)
        if line is None and combined:
            tools = _format_tools_suffix(message)
            line = (
                f"[{message.get('timestamp', '?')[:16]}] "
                f"{message.get('role', 'user').upper()}{tools}: {combined}"
            )
        elif line and doc_parts:
            line = f"{line}\n" + "\n".join(doc_parts)
        if line:
            lines.append(line)

    return "\n".join(lines), image_blocks


def has_archivable_content(formatted_text: str, image_blocks: list[dict[str, Any]]) -> bool:
    return bool(formatted_text.strip() or image_blocks)


# ---------------------------------------------------------------------------
# Consolidator — lightweight token-budget triggered consolidation
# ---------------------------------------------------------------------------


# Individual history.jsonl writers cap their own payloads tightly; the
# _HISTORY_ENTRY_HARD_CAP at append_history() is a belt-and-suspenders default
# that catches any new caller that forgot to set its own cap.
_RAW_ARCHIVE_MAX_CHARS = 16_000       # fallback dump (LLM failed)
_ARCHIVE_SUMMARY_MAX_CHARS = 8_000    # LLM-produced consolidation summary
_HISTORY_ENTRY_HARD_CAP = 64_000      # emergency cap in append_history


class Consolidator:
    """Lightweight consolidation: summarizes evicted messages into history.jsonl."""

    _MAX_CONSOLIDATION_ROUNDS = 5

    _SAFETY_BUFFER = 1024  # extra headroom for tokenizer estimation drift

    def __init__(
        self,
        store: MemoryStore,
        provider: LLMProvider,
        model: str,
        sessions: SessionManager,
        context_window_tokens: int,
        build_messages: Callable[..., list[dict[str, Any]]],
        get_tool_definitions: Callable[[], list[dict[str, Any]]],
        max_completion_tokens: int = 4096,
        consolidation_ratio: float = 0.5,
        workspace: Path | None = None,
        archive_media_max_bytes: int = 10_485_760,
        archive_extract_max_chars: int = 8_000,
        archive_bootstrap_max_chars: int = 12_000,
        archive_max_images: int = 5,
    ):
        self.store = store
        self.provider = provider
        self.model = model
        self.sessions = sessions
        self.context_window_tokens = context_window_tokens
        self.max_completion_tokens = max_completion_tokens
        self.consolidation_ratio = consolidation_ratio
        self.workspace = (workspace or store.workspace).expanduser().resolve()
        self.archive_media_max_bytes = archive_media_max_bytes
        self.archive_extract_max_chars = archive_extract_max_chars
        self.archive_bootstrap_max_chars = archive_bootstrap_max_chars
        self.archive_max_images = archive_max_images
        self._build_messages = build_messages
        self._get_tool_definitions = get_tool_definitions
        self._locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    def set_provider(
        self,
        provider: LLMProvider,
        model: str,
        context_window_tokens: int,
    ) -> None:
        self.provider = provider
        self.model = model
        self.context_window_tokens = context_window_tokens
        self.max_completion_tokens = provider.generation.max_tokens

    def get_lock(self, session_key: str) -> asyncio.Lock:
        """Return the shared consolidation lock for one session."""
        return self._locks.setdefault(session_key, asyncio.Lock())

    def pick_consolidation_boundary(
        self,
        session: Session,
        tokens_to_remove: int,
    ) -> tuple[int, int] | None:
        """Pick a user-turn boundary that removes enough old prompt tokens."""
        start = session.last_consolidated
        if start >= len(session.messages) or tokens_to_remove <= 0:
            return None

        removed_tokens = 0
        last_boundary: tuple[int, int] | None = None
        for idx in range(start, len(session.messages)):
            message = session.messages[idx]
            if idx > start and message.get("role") == "user":
                last_boundary = (idx, removed_tokens)
                if removed_tokens >= tokens_to_remove:
                    return last_boundary
            removed_tokens += estimate_message_tokens(message)

        return last_boundary

    @staticmethod
    def _full_unconsolidated_history(
        session: Session,
        *,
        include_timestamps: bool = False,
    ) -> list[dict[str, Any]]:
        """Return the whole unconsolidated tail for consolidation decisions."""
        unconsolidated_count = len(session.messages) - session.last_consolidated
        if unconsolidated_count <= 0:
            return []
        return session.get_history(
            max_messages=unconsolidated_count,
            include_timestamps=include_timestamps,
        )

    @staticmethod
    def _replay_overflow_boundary(
        session: Session,
        replay_max_messages: int | None,
    ) -> int | None:
        if not replay_max_messages or replay_max_messages <= 0:
            return None
        tail = list(enumerate(session.messages[session.last_consolidated:], session.last_consolidated))
        if len(tail) <= replay_max_messages:
            return None

        sliced = tail[-replay_max_messages:]
        for i, (_idx, message) in enumerate(sliced):
            if message.get("role") == "user":
                start = i
                if i > 0 and sliced[i - 1][1].get("_channel_delivery"):
                    start = i - 1
                sliced = sliced[start:]
                break

        legal_start = find_legal_message_start([message for _idx, message in sliced])
        if legal_start:
            sliced = sliced[legal_start:]
        if not sliced:
            return len(session.messages)

        first_visible_idx = sliced[0][0]
        if first_visible_idx <= session.last_consolidated:
            return None
        return first_visible_idx

    async def _consolidate_replay_overflow(
        self,
        session: Session,
        replay_max_messages: int | None,
    ) -> str | None:
        """Archive messages that would be hidden by the replay message window."""
        end_idx = self._replay_overflow_boundary(session, replay_max_messages)
        if end_idx is None:
            return None
        start_idx = eager_consolidation_start(session)
        if end_idx <= start_idx:
            session.last_consolidated = end_idx
            self.sessions.save(session)
            return None
        chunk = session.messages[start_idx:end_idx]
        if not chunk:
            session.last_consolidated = end_idx
            self.sessions.save(session)
            return None
        logger.info(
            "Replay-window consolidation for {}: chunk={} msgs, replay_max={}",
            session.key,
            len(chunk),
            replay_max_messages,
        )
        summary = await self.archive(chunk)
        session.last_consolidated = end_idx
        self.sessions.save(session)
        return summary

    def _persist_last_summary(self, session: Session, summary: str | None) -> None:
        normalized = _normalize_archive_summary(summary)
        if normalized:
            session.metadata["_last_summary"] = {
                "text": normalized,
                "last_active": session.updated_at.isoformat(),
            }
            self.sessions.save(session)

    def estimate_session_prompt_tokens(
        self,
        session: Session,
    ) -> tuple[int, str]:
        """Estimate prompt size from the full unconsolidated session tail."""
        history = self._full_unconsolidated_history(session, include_timestamps=True)
        channel, chat_id = (session.key.split(":", 1) if ":" in session.key else (None, None))
        # Include archived summary in estimation so the budget accounts for it.
        meta = session.metadata.get("_last_summary")
        summary = meta.get("text") if isinstance(meta, dict) else (meta if isinstance(meta, str) else None)
        probe_messages = self._build_messages(
            history=history,
            current_message="[token-probe]",
            channel=channel,
            chat_id=chat_id,
            sender_id=None,
            session_summary=summary,
            session_metadata=session.metadata,
        )
        return estimate_prompt_tokens_chain(
            self.provider,
            self.model,
            probe_messages,
            self._get_tool_definitions(),
        )

    @property
    def _input_token_budget(self) -> int:
        """Available input token budget for consolidation LLM."""
        return self.context_window_tokens - self.max_completion_tokens - self._SAFETY_BUFFER

    def _truncate_to_token_budget(self, text: str, *, max_tokens: int | None = None) -> str:
        """Truncate text so it fits within the consolidation LLM's token budget."""
        budget = self._input_token_budget if max_tokens is None else max_tokens
        if budget <= 0:
            return truncate_text(text, _RAW_ARCHIVE_MAX_CHARS)
        try:
            enc = tiktoken.get_encoding("cl100k_base")
            tokens = enc.encode(text)
            if len(tokens) <= budget:
                return text
            return enc.decode(tokens[:budget]) + "\n... (truncated)"
        except Exception:
            return truncate_text(text, budget * 4)

    def _load_bootstrap_context(self) -> str:
        """Load workspace bootstrap files for archive dedup reference."""
        parts: list[str] = []
        for filename in _ARCHIVE_BOOTSTRAP_FILES:
            file_path = self.workspace / filename
            if not file_path.exists():
                continue
            try:
                content = file_path.read_text(encoding="utf-8")
            except OSError:
                logger.debug("Skipping unreadable bootstrap file {}", file_path)
                continue
            if _is_workspace_template_content(content, filename):
                continue
            parts.append(f"## {filename}\n\n{content}")
        combined = "\n\n".join(parts)
        if not combined:
            return ""
        if self.archive_bootstrap_max_chars > 0 and len(combined) > self.archive_bootstrap_max_chars:
            combined = (
                truncate_text(combined, self.archive_bootstrap_max_chars)
                + " … (bootstrap truncated for archive)"
            )
        return combined

    def _build_archive_payload(
        self,
        messages: list[dict[str, Any]],
    ) -> tuple[str, list[dict[str, Any]]]:
        return format_messages_for_archive(
            messages,
            max_media_bytes=self.archive_media_max_bytes,
            extract_max_chars=self.archive_extract_max_chars,
            max_images=self.archive_max_images,
        )

    def _truncate_archive_payload(
        self,
        system_text: str,
        transcript_text: str,
        image_count: int,
    ) -> str | None:
        """Fit transcript text into remaining input budget after system and images."""
        if image_count > 0 and not transcript_text.strip():
            return ""
        input_budget = self._input_token_budget
        if input_budget <= 0:
            return truncate_text(transcript_text, _RAW_ARCHIVE_MAX_CHARS)
        system_tokens = _estimate_text_tokens(system_text)
        image_reserve = image_count * ARCHIVE_IMAGE_TOKEN_RESERVE
        transcript_budget = (
            input_budget - system_tokens - image_reserve - ARCHIVE_SYSTEM_OVERHEAD
        )
        if transcript_budget <= 0:
            return None if image_count == 0 else ""
        return self._truncate_to_token_budget(
            transcript_text,
            max_tokens=min(transcript_budget, input_budget),
        )

    def _build_archive_user_content(
        self,
        transcript_text: str,
        image_blocks: list[dict[str, Any]],
    ) -> str | list[dict[str, Any]]:
        header = _ARCHIVE_TRANSCRIPT_HEADER
        body = transcript_text.strip() or "(see images above)"
        text = f"{header}{body}"
        if not image_blocks:
            return text
        return [*image_blocks, {"type": "text", "text": text}]

    def _raw_archive_fallback(self, messages: list[dict[str, Any]]) -> None:
        """Fallback: dump formatted messages without LLM summarization."""
        formatted_text, image_blocks = self._build_archive_payload(messages)
        if not has_archivable_content(formatted_text, image_blocks):
            return
        bootstrap = self._load_bootstrap_context()
        system = render_template(
            "agent/consolidator_archive.md",
            strip=True,
            bootstrap_context=bootstrap,
        )
        truncated = self._truncate_archive_payload(system, formatted_text, 0)
        if truncated is None:
            return
        for block in image_blocks:
            path = (block.get("_meta") or {}).get("path", "")
            if path:
                truncated += f"\n[image: {path}]"
        truncated = truncate_text(truncated, _RAW_ARCHIVE_MAX_CHARS)
        self.store.append_history(
            f"[RAW] {len(messages)} messages\n{truncated}",
            max_chars=_RAW_ARCHIVE_MAX_CHARS,
        )
        logger.warning(
            "Memory consolidation degraded: raw-archived {} messages", len(messages)
        )

    async def archive(self, messages: list[dict]) -> str | None:
        """Summarize messages via LLM and append to history.jsonl.

        Returns the summary text on success, None if nothing to archive.
        """
        if not messages:
            return None

        formatted_text, image_blocks = self._build_archive_payload(messages)
        if not has_archivable_content(formatted_text, image_blocks):
            return None

        bootstrap = self._load_bootstrap_context()
        system = render_template(
            "agent/consolidator_archive.md",
            strip=True,
            bootstrap_context=bootstrap,
        )
        vision_count = _count_archive_vision_images(image_blocks)
        truncated = self._truncate_archive_payload(
            system,
            formatted_text,
            vision_count,
        )
        if truncated is None and vision_count == 0:
            return None

        user_content = self._build_archive_user_content(truncated or "", image_blocks)

        try:
            response = await self.provider.chat_with_retry(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_content},
                ],
                tools=None,
                tool_choice=None,
            )
            if response.finish_reason == "error":
                raise RuntimeError(f"LLM returned error: {response.content}")
            summary = _normalize_archive_summary(response.content)
            if summary is None:
                return None
            self.store.append_history(summary, max_chars=_ARCHIVE_SUMMARY_MAX_CHARS)
            return summary
        except Exception:
            logger.warning("Consolidation LLM call failed, raw-dumping to history")
            self._raw_archive_fallback(messages)
            return None

    async def maybe_consolidate_by_tokens(
        self,
        session: Session,
        *,
        replay_max_messages: int | None = None,
    ) -> None:
        """Loop: archive old messages until prompt fits within safe budget.

        The budget reserves space for completion tokens and a safety buffer
        so the LLM request never exceeds the context window.
        """
        if self.context_window_tokens <= 0:
            return

        lock = self.get_lock(session.key)
        async with lock:
            # Refresh session reference: AutoCompact may have replaced it.
            fresh = self.sessions.get_or_create(session.key)
            if fresh is not session:
                session = fresh
            if not session.messages:
                return

            budget = self._input_token_budget
            target = int(budget * self.consolidation_ratio)
            last_summary = await self._consolidate_replay_overflow(
                session,
                replay_max_messages,
            )
            try:
                estimated, source = self.estimate_session_prompt_tokens(
                    session,
                )
            except Exception:
                logger.exception("Token estimation failed for {}", session.key)
                estimated, source = 0, "error"
            if estimated <= 0:
                self._persist_last_summary(session, last_summary)
                return
            if estimated < budget:
                unconsolidated_count = len(session.messages) - session.last_consolidated
                logger.debug(
                    "Token consolidation idle {}: {}/{} via {}, msgs={}",
                    session.key,
                    estimated,
                    self.context_window_tokens,
                    source,
                    unconsolidated_count,
                )
                self._persist_last_summary(session, last_summary)
                return

            for round_num in range(self._MAX_CONSOLIDATION_ROUNDS):
                if estimated <= target:
                    break

                boundary = self.pick_consolidation_boundary(session, max(1, estimated - target))
                if boundary is None:
                    logger.debug(
                        "Token consolidation: no safe boundary for {} (round {})",
                        session.key,
                        round_num,
                    )
                    break

                end_idx = boundary[0]

                start_idx = eager_consolidation_start(session)
                if end_idx <= start_idx:
                    session.last_consolidated = end_idx
                    self.sessions.save(session)
                    try:
                        estimated, source = self.estimate_session_prompt_tokens(
                            session,
                        )
                    except Exception:
                        logger.exception(
                            "Token estimation failed for {}", session.key
                        )
                        estimated, source = 0, "error"
                    if estimated <= target:
                        break
                    continue

                chunk = session.messages[start_idx:end_idx]
                if not chunk:
                    session.last_consolidated = end_idx
                    self.sessions.save(session)
                    break

                logger.info(
                    "Token consolidation round {} for {}: {}/{} via {}, chunk={} msgs",
                    round_num,
                    session.key,
                    estimated,
                    self.context_window_tokens,
                    source,
                    len(chunk),
                )
                summary = await self.archive(chunk)
                # Advance the cursor either way: on success the chunk was
                # summarized; on failure archive() already raw-archived it as
                # a breadcrumb. Re-archiving the same chunk on the next call
                # would just emit duplicate [RAW] entries.
                if summary:
                    last_summary = summary
                session.last_consolidated = end_idx
                self.sessions.save(session)
                if not summary:
                    # LLM is degraded — stop hammering it this call;
                    # the next invocation can retry a fresh chunk.
                    break

                try:
                    estimated, source = self.estimate_session_prompt_tokens(
                        session,
                    )
                except Exception:
                    logger.exception("Token estimation failed for {}", session.key)
                    estimated, source = 0, "error"
                if estimated <= 0:
                    break

            # Persist the last summary to session metadata so it can be injected
            # into the runtime context on the next prepare_session() call, aligning
            # the summary injection strategy with AutoCompact._archive().
            self._persist_last_summary(session, last_summary)

    async def compact_idle_session(
        self,
        session_key: str,
        max_suffix: int = 8,
    ) -> str | None:
        """Hard-truncate an idle session under the consolidation lock.

        Used by AutoCompact so all session mutation goes through a single
        lock-protected path.  Returns the summary text on success, ``None``
        if the LLM failed (raw_archive fallback), or ``""`` if there was
        nothing to archive.
        """
        lock = self.get_lock(session_key)
        async with lock:
            self.sessions.invalidate(session_key)
            session = self.sessions.get_or_create(session_key)

            tail = list(session.messages[session.last_consolidated:])
            if not tail:
                session.updated_at = datetime.now()
                self.sessions.save(session)
                return ""

            probe = Session(
                key=session.key,
                messages=tail.copy(),
                created_at=session.created_at,
                updated_at=session.updated_at,
                metadata={},
                last_consolidated=0,
            )
            probe.retain_recent_legal_suffix(max_suffix)
            kept = probe.messages
            cut = len(tail) - len(kept)
            archive_msgs = tail[:cut]

            if not archive_msgs and not kept:
                session.updated_at = datetime.now()
                self.sessions.save(session)
                return ""

            last_active = session.updated_at
            summary: str | None = ""
            if archive_msgs:
                summary = await self.archive(archive_msgs)

            if summary and summary != "(nothing)":
                session.metadata["_last_summary"] = {
                    "text": summary,
                    "last_active": last_active.isoformat(),
                }

            session.messages = kept
            session.last_consolidated = 0
            session.updated_at = datetime.now()
            self.sessions.save(session)

            if archive_msgs:
                logger.info(
                    "Idle-session compact for {}: archived={}, kept={}, summary={}",
                    session_key,
                    len(archive_msgs),
                    len(kept),
                    bool(summary),
                )

            return summary


# ---------------------------------------------------------------------------
# Dream — heavyweight cron-scheduled memory consolidation
# ---------------------------------------------------------------------------


# Single source of truth for the staleness threshold used in _annotate_with_ages
# *and* in the Phase 1 prompt template (passed as `stale_threshold_days`).
# Keep code and prompt aligned — if you bump this, the LLM's instruction string
# updates automatically.
_STALE_THRESHOLD_DAYS = 14


class Dream:
    """Two-phase memory processor: analyze history.jsonl, then edit files via AgentRunner.

    Phase 1 produces an analysis summary (plain LLM call).
    Phase 2 delegates to AgentRunner with read_file / edit_file tools so the
    LLM can make targeted, incremental edits instead of replacing entire files.
    """

    # Caps on prompt-bound inputs so Dream's LLM calls never exceed the model's
    # context window just because a file (or a legacy large history entry) grew
    # unexpectedly. Each file still appears in full via read_file when the agent
    # needs it in Phase 2 — these caps only bound the Phase 1/2 prompt preview.
    _MEMORY_FILE_MAX_CHARS = 32_000
    _SOUL_FILE_MAX_CHARS = 16_000
    _USER_FILE_MAX_CHARS = 16_000
    _HISTORY_ENTRY_PREVIEW_MAX_CHARS = 4_000
    _DEFERRED_STALE_EDIT_MAX_CHARS = 8_000
    _STALE_EDIT_RE = re.compile(r"old_text not found in ([^.\n]+(?:\.[^.\s\n]+)?)")

    def __init__(
        self,
        store: MemoryStore,
        provider: LLMProvider,
        model: str,
        max_batch_size: int = 20,
        max_iterations: int = 10,
        max_tool_result_chars: int = 16_000,
        annotate_line_ages: bool = True,
    ):
        self.store = store
        self.provider = provider
        self.model = model
        self.max_batch_size = max_batch_size
        self.max_iterations = max_iterations
        self.max_tool_result_chars = max_tool_result_chars
        # Kill switch for the git-blame-based per-line age annotation in Phase 1.
        # Default True keeps the #3212 behavior; set False to feed MEMORY.md raw
        # (e.g. if a specific LLM reacts poorly to the `← Nd` suffix).
        self.annotate_line_ages = annotate_line_ages
        self._runner = AgentRunner(provider)
        self._tools = self._build_tools()

    def set_provider(self, provider: LLMProvider, model: str) -> None:
        self.provider = provider
        self.model = model
        self._runner.provider = provider

    # -- tool registry -------------------------------------------------------

    def _build_tools(self) -> ToolRegistry:
        """Build a minimal tool registry for the Dream agent."""
        from nanobot.agent.skills import BUILTIN_SKILLS_DIR
        from nanobot.agent.tools.file_state import FileStates
        from nanobot.agent.tools.filesystem import EditFileTool, ReadFileTool, WriteFileTool

        tools = ToolRegistry()
        workspace = self.store.workspace
        # Allow reading builtin skills for reference during skill creation
        extra_read = [BUILTIN_SKILLS_DIR] if BUILTIN_SKILLS_DIR.exists() else None
        # Dream gets its own FileStates so its caches stay isolated from the
        # main loop's sessions (issue #3571).
        file_states = FileStates()
        tools.register(ReadFileTool(
            workspace=workspace,
            allowed_dir=workspace,
            extra_allowed_dirs=extra_read,
            file_states=file_states,
        ))
        tools.register(EditFileTool(workspace=workspace, allowed_dir=workspace, file_states=file_states))
        # write_file resolves relative paths from workspace root, but can only
        # write under skills/ so the prompt can safely use skills/<name>/SKILL.md.
        skills_dir = workspace / "skills"
        skills_dir.mkdir(parents=True, exist_ok=True)
        tools.register(WriteFileTool(workspace=workspace, allowed_dir=skills_dir, file_states=file_states))
        return tools

    # -- skill listing --------------------------------------------------------

    def _list_existing_skills(self) -> list[str]:
        """List existing skills as 'name — description' for dedup context."""
        import re as _re

        from nanobot.agent.skills import BUILTIN_SKILLS_DIR

        desc_re = _re.compile(r"^description:\s*(.+)$", _re.MULTILINE | _re.IGNORECASE)
        entries: dict[str, str] = {}
        for base in (self.store.workspace / "skills", BUILTIN_SKILLS_DIR):
            if not base.exists():
                continue
            for d in base.iterdir():
                if not d.is_dir():
                    continue
                skill_md = d / "SKILL.md"
                if not skill_md.exists():
                    continue
                # Prefer workspace skills over builtin (same name)
                if d.name in entries and base == BUILTIN_SKILLS_DIR:
                    continue
                content = skill_md.read_text(encoding="utf-8")[:500]
                m = desc_re.search(content)
                desc = m.group(1).strip() if m else "(no description)"
                entries[d.name] = desc
        return [f"{name} — {desc}" for name, desc in sorted(entries.items())]

    def _repeated_stale_edit_paths(self, result: Any | None) -> list[str]:
        """Return paths with repeated stale edit_file failures in a Dream run."""
        if not result:
            return []
        counts: dict[str, int] = {}
        for event in result.tool_events or []:
            if event.get("name") != "edit_file" or event.get("status") != "error":
                continue
            match = self._STALE_EDIT_RE.search(event.get("detail", ""))
            if not match:
                continue
            path = match.group(1)
            counts[path] = counts.get(path, 0) + 1

        if counts:
            return sorted(path for path, count in counts.items() if count >= 2)

        for message in result.messages or []:
            if message.get("role") != "tool" or message.get("name") != "edit_file":
                continue
            content = str(message.get("content") or "")
            match = self._STALE_EDIT_RE.search(content)
            if not match:
                continue
            path = match.group(1)
            counts[path] = counts.get(path, 0) + 1

        return sorted(path for path, count in counts.items() if count >= 2)

    def _defer_stale_edit_batch(
        self,
        *,
        batch: list[dict[str, Any]],
        analysis: str,
        paths: list[str],
    ) -> int:
        """Persist a compact breadcrumb so a stale edit loop does not replay forever."""
        start_cursor = batch[0]["cursor"]
        end_cursor = batch[-1]["cursor"]
        path_text = ", ".join(paths) if paths else "(unknown)"
        entry = (
            "[DREAM-DEFERRED stale-edit]\n"
            f"Cursor range: {start_cursor}-{end_cursor}\n"
            f"Files with repeated old_text misses: {path_text}\n\n"
            "Dream could not finish applying the analysis because repeated edit_file "
            "calls targeted text that was no longer present. Re-evaluate this analysis "
            "against the current memory files; skip facts already present.\n\n"
            f"{analysis.strip()}"
        )
        return self.store.append_history(entry, max_chars=self._DEFERRED_STALE_EDIT_MAX_CHARS)

    # -- main entry ----------------------------------------------------------

    def _annotate_with_ages(self, content: str) -> str:
        """Append per-line age suffixes to MEMORY.md content.

        Each non-blank line whose age exceeds ``_STALE_THRESHOLD_DAYS`` gets a
        suffix like ``← 30d`` indicating days since last modification.
        Returns the original content unchanged if git is unavailable,
        annotate fails, or the line count doesn't match the age count
        (which can happen with an uncommitted working-tree edit — better to
        skip annotation than to tag the wrong line).
        SOUL.md and USER.md are never annotated.
        """
        file_path = "memory/MEMORY.md"
        try:
            ages = self.store.git.line_ages(file_path)
        except Exception:
            logger.debug("line_ages failed for {}", file_path)
            return content
        if not ages:
            return content

        had_trailing = content.endswith("\n")
        lines = content.splitlines()
        # If HEAD-blob line count disagrees with the working-tree content we
        # received, ages would be assigned to the wrong lines — skip entirely
        # and feed the LLM un-annotated content rather than misleading data.
        if len(lines) != len(ages):
            logger.debug(
                "line_ages length mismatch for {} (lines={}, ages={}); skipping annotation",
                file_path, len(lines), len(ages),
            )
            return content

        annotated: list[str] = []
        for line, age in zip(lines, ages):
            if not line.strip():
                annotated.append(line)
                continue
            if age.age_days > _STALE_THRESHOLD_DAYS:
                annotated.append(f"{line}  \u2190 {age.age_days}d")
            else:
                annotated.append(line)
        result = "\n".join(annotated)
        if had_trailing:
            result += "\n"
        return result

    async def run(self) -> bool:
        """Process unprocessed history entries. Returns True if work was done."""
        from nanobot.agent.skills import BUILTIN_SKILLS_DIR

        last_cursor = self.store.get_last_dream_cursor()
        entries = self.store.read_unprocessed_history(since_cursor=last_cursor)
        if not entries:
            return False

        batch = entries[: self.max_batch_size]
        logger.info(
            "Dream: processing {} entries (cursor {}→{}), batch={}",
            len(entries), last_cursor, batch[-1]["cursor"], len(batch),
        )

        # Build history text for LLM — cap each entry so a legacy oversized
        # record (e.g. pre-#3412 raw_archive dump) can't blow up the prompt.
        history_text = "\n".join(
            f"[{e['timestamp']}] "
            f"{truncate_text(e['content'], self._HISTORY_ENTRY_PREVIEW_MAX_CHARS)}"
            for e in batch
        )

        # Current file contents + per-line age annotations (MEMORY.md only).
        # Each file is capped in the *prompt preview* only; Phase 2 still sees
        # the full file via the read_file tool.
        current_date = datetime.now().strftime("%Y-%m-%d")
        raw_memory = self.store.read_memory() or "(empty)"
        annotated_memory = (
            self._annotate_with_ages(raw_memory)
            if self.annotate_line_ages
            else raw_memory
        )
        current_memory = truncate_text(annotated_memory, self._MEMORY_FILE_MAX_CHARS)
        current_soul = truncate_text(
            self.store.read_soul() or "(empty)", self._SOUL_FILE_MAX_CHARS,
        )
        current_user = truncate_text(
            self.store.read_user() or "(empty)", self._USER_FILE_MAX_CHARS,
        )

        file_context = (
            f"## Current Date\n{current_date}\n\n"
            f"## Current MEMORY.md ({len(current_memory)} chars)\n{current_memory}\n\n"
            f"## Current SOUL.md ({len(current_soul)} chars)\n{current_soul}\n\n"
            f"## Current USER.md ({len(current_user)} chars)\n{current_user}"
        )

        # Phase 1: Analyze (no skills list — dedup is Phase 2's job)
        phase1_prompt = (
            f"## Conversation History\n{history_text}\n\n{file_context}"
        )

        try:
            phase1_response = await self.provider.chat_with_retry(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": render_template(
                            "agent/dream_phase1.md",
                            strip=True,
                            stale_threshold_days=_STALE_THRESHOLD_DAYS,
                        ),
                    },
                    {"role": "user", "content": phase1_prompt},
                ],
                tools=None,
                tool_choice=None,
            )
            analysis = phase1_response.content or ""
            logger.debug("Dream Phase 1 analysis ({} chars): {}", len(analysis), analysis[:500])
        except Exception:
            logger.exception("Dream Phase 1 failed")
            return False

        # Phase 2: Delegate to AgentRunner with read_file / edit_file
        existing_skills = self._list_existing_skills()
        skills_section = ""
        if existing_skills:
            skills_section = (
                "\n\n## Existing Skills\n"
                + "\n".join(f"- {s}" for s in existing_skills)
            )
        phase2_prompt = f"## Analysis Result\n{analysis}\n\n{file_context}{skills_section}"

        tools = self._tools
        skill_creator_path = BUILTIN_SKILLS_DIR / "skill-creator" / "SKILL.md"
        messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": render_template(
                    "agent/dream_phase2.md",
                    strip=True,
                    skill_creator_path=str(skill_creator_path),
                ),
            },
            {"role": "user", "content": phase2_prompt},
        ]

        try:
            result = await self._runner.run(AgentRunSpec(
                initial_messages=messages,
                tools=tools,
                model=self.model,
                max_iterations=self.max_iterations,
                max_tool_result_chars=self.max_tool_result_chars,
                fail_on_tool_error=False,
            ))
            logger.debug(
                "Dream Phase 2 complete: stop_reason={}, tool_events={}",
                result.stop_reason, len(result.tool_events),
            )
            for ev in (result.tool_events or []):
                logger.info("Dream tool_event: name={}, status={}, detail={}", ev.get("name"), ev.get("status"), ev.get("detail", "")[:200])
        except Exception:
            logger.exception("Dream Phase 2 failed")
            result = None

        # Build changelog from tool events
        changelog: list[str] = []
        if result and result.tool_events:
            for event in result.tool_events:
                if event["status"] == "ok":
                    changelog.append(f"{event['name']}: {event['detail']}")

        # Only advance cursor on successful completion to prevent silent loss
        if result and result.stop_reason == "completed":
            new_cursor = batch[-1]["cursor"]
            self.store.set_last_dream_cursor(new_cursor)
            logger.info(
                "Dream done: {} change(s), cursor advanced to {}",
                len(changelog), new_cursor,
            )
        else:
            reason = result.stop_reason if result else "exception"
            stale_paths = (
                self._repeated_stale_edit_paths(result)
                if reason == "max_iterations"
                else []
            )
            if stale_paths:
                deferred_cursor = self._defer_stale_edit_batch(
                    batch=batch,
                    analysis=analysis,
                    paths=stale_paths,
                )
                new_cursor = batch[-1]["cursor"]
                self.store.set_last_dream_cursor(new_cursor)
                logger.warning(
                    "Dream deferred stale edit loop for {} (deferred cursor {}); "
                    "cursor advanced to {}",
                    ", ".join(stale_paths), deferred_cursor, new_cursor,
                )
            else:
                logger.warning(
                    "Dream incomplete ({}): cursor NOT advanced, will retry next cron cycle",
                    reason,
                )

        self.store.compact_history()

        # Git auto-commit (only when there are actual changes)
        if changelog and self.store.git.is_initialized():
            ts = batch[-1]["timestamp"]
            summary = f"dream: {ts}, {len(changelog)} change(s)"
            commit_msg = f"{summary}\n\n{analysis.strip()}"
            sha = self.store.git.auto_commit(commit_msg)
            if sha:
                logger.info("Dream commit: {}", sha)

        return True
