"""Content guard orchestration: chunking, backend dispatch, async wrapper."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from loguru import logger

from nanobot.contrib.web_guard.config import WebFetchContentGuardSettings

# ~512 tokens at ~4 chars/token (models cap context at 512 tokens).
_CHUNK_CHARS = 2048
_CHUNK_OVERLAP = 256

_BACKENDS = ("cliguard", "prompt-guard")


@dataclass(frozen=True)
class GuardScanResult:
    """Outcome of classifying fetched web text."""

    blocked: bool
    backend: str
    reason: str = ""
    scan_failed: bool = False
    details: dict[str, Any] = field(default_factory=dict)


def chunk_text(text: str, *, max_chars: int = _CHUNK_CHARS, overlap: int = _CHUNK_OVERLAP) -> list[str]:
    """Split long text into overlapping chunks for classifier input."""
    text = text.strip()
    if not text:
        return []
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        chunks.append(text[start:end])
        if end >= len(text):
            break
        start = max(0, end - overlap)
    return chunks


def _normalize_backend(name: str) -> str:
    normalized = (name or "cliguard").strip().lower().replace("_", "-")
    if normalized not in _BACKENDS:
        raise ValueError(f"Unknown web guard backend: {name!r} (expected one of {_BACKENDS})")
    return normalized


def _classify_sync(text: str, settings: WebFetchContentGuardSettings) -> GuardScanResult:
    backend = _normalize_backend(settings.backend)
    sample = text[: settings.max_input_chars]
    chunks = chunk_text(sample)
    if not chunks:
        return GuardScanResult(blocked=False, backend=backend, reason="empty")

    if backend == "cliguard":
        from nanobot.contrib.web_guard.backends import cliguard

        return cliguard.classify_chunks(chunks, settings)
    from nanobot.contrib.web_guard.backends import prompt_guard

    return prompt_guard.classify_chunks(chunks, settings)


async def run_content_guard(
    *,
    url: str,
    text: str,
    settings: WebFetchContentGuardSettings,
) -> GuardScanResult:
    """Classify fetched text; fail-closed when configured and the guard errors."""
    if not settings.enabled:
        return GuardScanResult(blocked=False, backend=settings.backend, reason="disabled")

    sample = text[: settings.max_input_chars]
    chunk_count = len(chunk_text(sample)) or (1 if sample.strip() else 0)
    try:
        classify_t0 = time.perf_counter()
        result = await asyncio.to_thread(_classify_sync, text, settings)
        classify_seconds = time.perf_counter() - classify_t0
        if result.blocked:
            logger.warning(
                "web_fetch_guard blocked url={} backend={} reason={} "
                "chunks={} seconds={:.3f}",
                url,
                result.backend,
                result.reason,
                chunk_count,
                classify_seconds,
            )
        else:
            logger.debug(
                "web_fetch_guard allowed url={} backend={} chunks={} seconds={:.3f}",
                url,
                result.backend,
                chunk_count,
                classify_seconds,
            )
        return result
    except ImportError as e:
        logger.error("web_fetch_guard missing dependency for backend={}: {}", settings.backend, e)
        if settings.fail_closed:
            return GuardScanResult(
                blocked=True,
                backend=settings.backend,
                reason="missing_dependency",
                scan_failed=True,
                details={"error": str(e)},
            )
        return GuardScanResult(
            blocked=False,
            backend=settings.backend,
            reason="missing_dependency_pass",
            scan_failed=True,
            details={"error": str(e)},
        )
    except Exception as e:
        logger.error("web_fetch_guard classify failed url={} error={}", url, e)
        if settings.fail_closed:
            return GuardScanResult(
                blocked=True,
                backend=settings.backend,
                reason="classify_error",
                scan_failed=True,
                details={"error": str(e)},
            )
        return GuardScanResult(
            blocked=False,
            backend=settings.backend,
            reason="classify_error_pass",
            scan_failed=True,
            details={"error": str(e)},
        )
