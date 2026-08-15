"""
Instagram-specific ephemeral draft handoff and Slack thread mapping.

Keeps tool/channel coordination out of core agent loop code.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock

from nanobot.config.paths import get_data_dir

_DRAFT_TTL_SECONDS = 600
_THREAD_MAP_FILE = "instagram_slack_threads.json"
_CHAT_ID_SEP = ":"

_lock = Lock()


def compose_chat_id(account_key: str, customer_sender_id: str) -> str:
    """Build a collision-safe conversation id for multi-account routing."""
    return f"{account_key}{_CHAT_ID_SEP}{customer_sender_id}"


def parse_chat_id(chat_id: str) -> tuple[str | None, str]:
    """Return ``(account_key, customer_sender_id)``; legacy ids have no account prefix."""
    if _CHAT_ID_SEP in chat_id:
        account_key, _, customer_id = chat_id.partition(_CHAT_ID_SEP)
        if account_key and customer_id:
            return account_key, customer_id
    return None, chat_id


@dataclass
class InstagramDraftPayload:
    """Draft queued by ``create_instagram_draft`` for the next review post."""

    draft_text: str
    review_notes: str = ""
    created_at: float = field(default_factory=time.time)


_pending_drafts: dict[str, InstagramDraftPayload] = {}


def set_draft(chat_id: str, draft_text: str, *, review_notes: str = "") -> None:
    """Store a draft for *chat_id* until the channel consumes it on turn completion."""
    with _lock:
        _expire_old_unlocked()
        _pending_drafts[str(chat_id)] = InstagramDraftPayload(
            draft_text=draft_text.strip(),
            review_notes=(review_notes or "").strip(),
        )


def consume_draft(chat_id: str) -> InstagramDraftPayload | None:
    """Remove and return the pending draft for *chat_id*, if any."""
    with _lock:
        _expire_old_unlocked()
        return _pending_drafts.pop(str(chat_id), None)


def peek_draft(chat_id: str) -> InstagramDraftPayload | None:
    """Return pending draft without removing it."""
    with _lock:
        _expire_old_unlocked()
        return _pending_drafts.get(str(chat_id))


def _expire_old_unlocked() -> None:
    now = time.time()
    expired = [
        key
        for key, payload in _pending_drafts.items()
        if now - payload.created_at > _DRAFT_TTL_SECONDS
    ]
    for key in expired:
        del _pending_drafts[key]


def _thread_map_path() -> Path:
    return get_data_dir() / _THREAD_MAP_FILE


def _load_thread_map() -> dict[str, str]:
    path = _thread_map_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if k and v}


def _save_thread_map(mapping: dict[str, str]) -> None:
    path = _thread_map_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")


def get_slack_thread_ts(chat_id: str) -> str | None:
    """Return persisted Slack ``thread_ts`` for an Instagram customer/chat id."""
    with _lock:
        return _load_thread_map().get(str(chat_id))


def set_slack_thread_ts(chat_id: str, thread_ts: str) -> None:
    """Persist Slack ``thread_ts`` anchor for an Instagram customer/chat id."""
    with _lock:
        mapping = _load_thread_map()
        mapping[str(chat_id)] = str(thread_ts)
        _save_thread_map(mapping)


def clear_slack_thread_ts(chat_id: str) -> None:
    """Drop stored Slack thread anchor (e.g. after parent message was deleted)."""
    with _lock:
        mapping = _load_thread_map()
        if str(chat_id) in mapping:
            del mapping[str(chat_id)]
            _save_thread_map(mapping)
