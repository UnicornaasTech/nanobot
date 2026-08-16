"""MSC3245 native voice message helpers for the Matrix channel (fork-specific)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

VOICE_MESSAGE_LABEL = "Voice message"
VOICE_MESSAGE_FILENAME = "Voice message.ogg"
_WAVEFORM_LENGTH = 100
_OGG_EXTENSIONS = {".ogg", ".oga", ".opus"}
_MATRIX_VOICE_KEY = "_matrix_voice"


def default_waveform(length: int = _WAVEFORM_LENGTH) -> list[int]:
    """Return a flat MSC3245 waveform (acceptable fallback for clients)."""
    return [0] * max(length, 1)


def _resolve_path_key(path: Path) -> str:
    try:
        return str(path.expanduser().resolve(strict=False))
    except OSError:
        return str(path.expanduser())


def resolve_path_key(path: Path) -> str:
    """Return a stable resolved path key for voice metadata matching."""
    return _resolve_path_key(path)


def parse_matrix_voice_metadata(
    metadata: dict[str, Any] | None,
    resolved_paths: list[Path],
) -> tuple[set[str], dict[str, Any]]:
    """Return voice path keys and optional per-message voice hints from metadata."""
    if not metadata:
        return set(), {}

    raw = metadata.get(_MATRIX_VOICE_KEY)
    if raw is True:
        return {_resolve_path_key(path) for path in resolved_paths}, {}

    if not isinstance(raw, dict):
        return set(), {}

    hints = dict(raw)
    explicit = hints.get("paths")
    if explicit is None:
        return {_resolve_path_key(path) for path in resolved_paths}, hints

    voice_keys: set[str] = set()
    if isinstance(explicit, list):
        for entry in explicit:
            if isinstance(entry, str) and entry.strip():
                voice_keys.add(_resolve_path_key(Path(entry.strip())))
    return voice_keys, hints


def voice_mime_for_path(path: Path, guessed_mime: str) -> str:
    """Prefer audio/ogg for common voice container extensions."""
    if path.suffix.lower() in _OGG_EXTENSIONS:
        return "audio/ogg"
    if guessed_mime.startswith("audio/"):
        return guessed_mime
    return guessed_mime


def audio_duration_ms(path: Path) -> int | None:
    """Read audio duration in milliseconds from an audio file via mutagen."""
    try:
        import mutagen
    except ImportError:
        return None

    try:
        audio = mutagen.File(path)
        if audio is None:
            return None
        length = audio.info.length
    except (OSError, mutagen.MutagenError, AttributeError):
        return None

    if not isinstance(length, (int, float)) or length <= 0:
        return None
    return max(1, int(length * 1000))


def resolve_voice_duration_ms(path: Path, hints: dict[str, Any]) -> int:
    """Resolve voice duration from metadata hints or audio file metadata."""
    raw = hints.get("duration_ms")
    if isinstance(raw, int) and raw > 0:
        return raw
    if isinstance(raw, float) and raw > 0:
        return max(1, int(raw))

    from_file = audio_duration_ms(path)
    if from_file is not None:
        return from_file
    return 1


def resolve_voice_waveform(hints: dict[str, Any]) -> list[int]:
    """Resolve MSC3245 waveform from metadata hints or use the default."""
    raw = hints.get("waveform")
    if isinstance(raw, list) and raw:
        waveform: list[int] = []
        for value in raw:
            if isinstance(value, (int, float)):
                waveform.append(max(0, min(1024, int(value))))
        if waveform:
            return waveform
    return default_waveform()


def build_voice_message_content(
    *,
    mime: str,
    size_bytes: int,
    duration_ms: int,
    waveform: list[int],
    mxc_url: str,
    encryption_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build MSC3245 voice message content with legacy m.audio fallback fields."""
    msc1767_file: dict[str, Any] = {
        "name": VOICE_MESSAGE_FILENAME,
        "mimetype": mime,
        "size": size_bytes,
    }
    if encryption_info:
        msc1767_file["file"] = {**encryption_info, "url": mxc_url}
    else:
        msc1767_file["url"] = mxc_url

    content: dict[str, Any] = {
        "msgtype": "m.audio",
        "body": VOICE_MESSAGE_LABEL,
        "info": {
            "mimetype": mime,
            "size": size_bytes,
            "duration": duration_ms,
        },
        "org.matrix.msc1767.text": VOICE_MESSAGE_LABEL,
        "org.matrix.msc1767.file": msc1767_file,
        "org.matrix.msc1767.audio": {
            "duration": duration_ms,
            "waveform": waveform,
        },
        "org.matrix.msc3245.voice": {},
        "org.matrix.msc2516.voice": {},
        "m.mentions": {},
    }
    if encryption_info:
        content["file"] = {**encryption_info, "url": mxc_url}
    else:
        content["url"] = mxc_url
    return content
