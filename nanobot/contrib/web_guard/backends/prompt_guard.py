"""Llama Prompt Guard 2 backend via transformers."""

from __future__ import annotations

import threading
import time
from typing import Any

from loguru import logger

from nanobot.contrib.web_guard.config import WebFetchContentGuardSettings
from nanobot.contrib.web_guard.guard import GuardScanResult

DEFAULT_MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-86M"

_classifier_cache: dict[str, Any] = {}
_classifier_lock = threading.Lock()


def _effective_model_id(settings: WebFetchContentGuardSettings) -> str:
    return (settings.model_id or "").strip() or DEFAULT_MODEL_ID


def _get_classifier(settings: WebFetchContentGuardSettings) -> Any:
    from transformers import pipeline

    model_id = _effective_model_id(settings)
    device = settings.effective_device()
    # pipeline device: -1 for cpu, 0+ for cuda; mps uses device_map in newer transformers
    if device == "cpu":
        pipe_device: int | str = -1
    else:
        pipe_device = device
    key = f"{model_id}:{pipe_device}"
    if key not in _classifier_cache:
        with _classifier_lock:
            if key not in _classifier_cache:
                load_t0 = time.perf_counter()
                _classifier_cache[key] = pipeline(
                    "text-classification",
                    model=model_id,
                    device=pipe_device,
                    truncation=True,
                    max_length=512,
                )
                logger.debug(
                    "web_fetch_guard prompt_guard model_loaded model_id={} device={} seconds={:.3f}",
                    model_id,
                    pipe_device,
                    time.perf_counter() - load_t0,
                )
    return _classifier_cache[key]


def _label_is_malicious(label: str) -> bool:
    normalized = label.strip().lower()
    return normalized in ("malicious", "label_1", "1", "unsafe")


def classify_chunks(
    chunks: list[str],
    settings: WebFetchContentGuardSettings,
) -> GuardScanResult:
    classifier = _get_classifier(settings)
    classify_t0 = time.perf_counter()
    with _classifier_lock:
        for idx, chunk in enumerate(chunks):
            chunk_t0 = time.perf_counter()
            outputs = classifier(chunk)
            chunk_seconds = time.perf_counter() - chunk_t0
            if not outputs:
                logger.debug(
                    "web_fetch_guard prompt_guard chunk_index={}/{} empty_output seconds={:.3f}",
                    idx,
                    len(chunks),
                    chunk_seconds,
                )
                continue
            top = outputs[0] if isinstance(outputs, list) else outputs
            if not isinstance(top, dict):
                continue
            label = str(top.get("label", ""))
            score = float(top.get("score", 0.0))
            logger.debug(
                "web_fetch_guard prompt_guard chunk_index={}/{} label={} score={:.3f} seconds={:.3f}",
                idx,
                len(chunks),
                label,
                score,
                chunk_seconds,
            )
            if _label_is_malicious(label) and score >= settings.threshold:
                return GuardScanResult(
                    blocked=True,
                    backend="prompt-guard",
                    reason="malicious",
                    details={"chunk_index": idx, "label": label, "score": score},
                )
    logger.debug(
        "web_fetch_guard prompt_guard allowed chunks={} seconds={:.3f}",
        len(chunks),
        time.perf_counter() - classify_t0,
    )
    return GuardScanResult(blocked=False, backend="prompt-guard", details={"chunks": len(chunks)})
