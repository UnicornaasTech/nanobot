"""GLiGuard (CliGuard) backend via gliner2."""

from __future__ import annotations

import threading
import time
from typing import Any

from loguru import logger

from nanobot.contrib.web_guard.config import WebFetchContentGuardSettings
from nanobot.contrib.web_guard.guard import GuardScanResult

DEFAULT_MODEL_ID = "fastino/gliguard-LLMGuardrails-300M"

JAILBREAK_LABELS = [
    "prompt_injection",
    "jailbreak_attempt",
    "policy_evasion",
    "instruction_override",
    "system_prompt_exfiltration",
    "data_exfiltration",
    "roleplay_bypass",
    "hypothetical_bypass",
    "obfuscated_attack",
    "multi_step_attack",
    "social_engineering",
    "benign",
]

JAILBREAK_TASK: dict[str, Any] = {
    "labels": JAILBREAK_LABELS,
    "multi_label": True,
    "cls_threshold": 0.4,
}

_model_cache: dict[str, Any] = {}
_model_lock = threading.Lock()


def _effective_model_id(settings: WebFetchContentGuardSettings) -> str:
    return (settings.model_id or "").strip() or DEFAULT_MODEL_ID


def _get_model(settings: WebFetchContentGuardSettings) -> Any:
    from gliner2 import GLiNER2

    model_id = _effective_model_id(settings)
    device = settings.effective_device()
    key = f"{model_id}:{device}"
    if key not in _model_cache:
        with _model_lock:
            if key not in _model_cache:
                load_t0 = time.perf_counter()
                model = GLiNER2.from_pretrained(model_id)
                model.to(device)
                _model_cache[key] = model
                logger.debug(
                    "web_fetch_guard cliguard model_loaded model_id={} device={} seconds={:.3f}",
                    model_id,
                    device,
                    time.perf_counter() - load_t0,
                )
    return _model_cache[key]


def _result_blocked(result: dict[str, Any]) -> tuple[bool, str]:
    if result.get("prompt_safety") == "unsafe":
        return True, "prompt_unsafe"
    jailbreak = result.get("jailbreak_detection")
    if isinstance(jailbreak, list):
        bad = [label for label in jailbreak if label != "benign"]
        if bad:
            return True, f"jailbreak:{','.join(bad)}"
    elif isinstance(jailbreak, str) and jailbreak and jailbreak != "benign":
        return True, f"jailbreak:{jailbreak}"
    return False, ""


def classify_chunks(
    chunks: list[str],
    settings: WebFetchContentGuardSettings,
) -> GuardScanResult:
    model = _get_model(settings)
    schema = {
        "prompt_safety": ["safe", "unsafe"],
        "jailbreak_detection": JAILBREAK_TASK,
    }
    threshold = settings.threshold

    classify_t0 = time.perf_counter()
    with _model_lock:
        results = model.batch_classify_text(
            chunks,
            schema,
            batch_size=min(8, len(chunks)),
            threshold=threshold,
        )
    classify_seconds = time.perf_counter() - classify_t0

    if not isinstance(results, list):
        results = [results]
    for idx, result in enumerate(results):
        if not isinstance(result, dict):
            continue
        blocked, reason = _result_blocked(result)
        if blocked:
            logger.debug(
                "web_fetch_guard cliguard blocked chunk_index={}/{} reason={} seconds={:.3f}",
                idx,
                len(chunks),
                reason,
                classify_seconds,
            )
            return GuardScanResult(
                blocked=True,
                backend="cliguard",
                reason=reason,
                details={"chunk_index": idx, "result": result},
            )
    logger.debug(
        "web_fetch_guard cliguard allowed chunks={} seconds={:.3f}",
        len(chunks),
        classify_seconds,
    )
    return GuardScanResult(blocked=False, backend="cliguard", details={"chunks": len(chunks)})
