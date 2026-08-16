"""Post-fetch guard: classify web content before returning to the agent."""

from __future__ import annotations

import json
import time
from typing import Any

from loguru import logger

from nanobot.agent.tools.web import _UNTRUSTED_BANNER
from nanobot.contrib.web_guard.config import WebFetchGuardSettings
from nanobot.contrib.web_guard.guard import run_content_guard

_CONTENT_BLOCKED = "Content withheld by web fetch guard."


def _split_untrusted_banner(text: str) -> tuple[str, str]:
    if text.startswith(_UNTRUSTED_BANNER):
        rest = text[len(_UNTRUSTED_BANNER) :].lstrip("\n")
        return _UNTRUSTED_BANNER, rest
    return "", text


def _blocked_tool_json(url: str) -> str:
    return json.dumps(
        {"error": _CONTENT_BLOCKED, "url": url, "reason": "content_blocked"},
        ensure_ascii=False,
    )


def _allow_payload(data: dict[str, Any], banner: str, body: str) -> dict[str, Any]:
    out = {**data}
    text = "\n\n".join(p for p in (banner, body) if p)
    out["text"] = text
    out["length"] = len(text)
    return out


async def postprocess_fetch_result(
    url: str,
    result: Any,
    settings: WebFetchGuardSettings,
) -> Any:
    """Run content guard on fetch output; return vanilla-shaped JSON or minimal error."""
    guard_cfg = settings.content_guard
    postprocess_t0 = time.perf_counter()

    if isinstance(result, list):
        if not guard_cfg.enabled:
            logger.debug("web_fetch_guard postprocess url={} skipped (guard disabled)", url)
            return result
        combined: list[str] = []
        for block in result:
            if (
                isinstance(block, dict)
                and block.get("type") == "text"
                and isinstance(block.get("text"), str)
            ):
                combined.append(block["text"])
        sample = "\n\n".join(combined)[: guard_cfg.max_input_chars]
        logger.debug(
            "web_fetch_guard postprocess url={} format=list text_chars={}",
            url,
            len(sample),
        )
        scan = await run_content_guard(url=url, text=sample, settings=guard_cfg)
        if scan.blocked:
            return _blocked_tool_json(url)
        logger.debug(
            "web_fetch_guard postprocess url={} format=list seconds={:.3f}",
            url,
            time.perf_counter() - postprocess_t0,
        )
        return result

    if not isinstance(result, str):
        return result
    try:
        data = json.loads(result)
    except json.JSONDecodeError:
        return result
    if not isinstance(data, dict) or "error" in data:
        return result
    if "text" not in data or not isinstance(data["text"], str):
        return result

    banner, body = _split_untrusted_banner(data["text"])
    if guard_cfg.enabled:
        logger.debug(
            "web_fetch_guard postprocess url={} format=json text_chars={} has_banner={}",
            url,
            len(body),
            bool(banner),
        )
        scan = await run_content_guard(url=url, text=body, settings=guard_cfg)
        if scan.blocked:
            logger.warning(
                "web_fetch_guard blocked url={} reason={} scan_failed={} seconds={:.3f}",
                url,
                scan.reason,
                scan.scan_failed,
                time.perf_counter() - postprocess_t0,
            )
            return _blocked_tool_json(url)
    else:
        logger.debug("web_fetch_guard postprocess url={} skipped (guard disabled)", url)

    allowed = _allow_payload(data, banner, body)
    logger.debug(
        "web_fetch_guard postprocess url={} format=json seconds={:.3f}",
        url,
        time.perf_counter() - postprocess_t0,
    )
    return json.dumps(allowed, ensure_ascii=False)
