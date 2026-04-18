"""Web fetch defense: post-process + factory for monkey-patched ``WebFetchTool``."""

from __future__ import annotations

import json
from typing import Any

from loguru import logger

from nanobot.agent.tools.web import _UNTRUSTED_BANNER, WebFetchTool, _validate_url_safe
from nanobot.security.web_fetch_block_policy import (
    llm_classifier_outcome,
    structural_outcome,
)
from nanobot.security.web_fetch_defense_env import (
    WebFetchDefenseSettings,
    load_fetch_defense_from_env,
)
from nanobot.security.web_fetch_domain_trust import trust_tier_for_url
from nanobot.security.web_fetch_safety_scan import (
    CLASSIFIER_MAX_INPUT_CHARS,
    run_safety_classification,
    safety_classifier_invoked,
)
from nanobot.security.web_fetch_sanitize import sanitize_web_fetch_text

_CONTENT_BLOCKED = "Content withheld by web fetch policy."


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


def _log_allowed(
    url: str,
    *,
    structural_severity: int | None = None,
    structural_detection_count: int | None = None,
    structural_skipped: bool | None = None,
    llm_verdict: str | None = None,
    llm_severity: int | None = None,
) -> None:
    logger.info(
        "web_fetch_defense allowed url={} structural_severity={} structural_detection_count={} "
        "structural_skipped={} llm_verdict={} llm_severity={}",
        url,
        structural_severity,
        structural_detection_count,
        structural_skipped,
        llm_verdict,
        llm_severity,
    )


def _log_blocked(url: str, block_code: str, **kwargs: Any) -> None:
    parts = [f"{k}={v}" for k, v in kwargs.items() if v is not None]
    tail = " ".join(parts)
    logger.warning(
        "web_fetch_defense blocked url={} block_code={} {}",
        url,
        block_code,
        tail,
    )


def _allow_payload(data: dict[str, Any], banner: str, body: str) -> dict[str, Any]:
    out = {**data}
    out.pop("structuralScan", None)
    out.pop("safetyScan", None)
    text = "\n\n".join(p for p in (banner, body) if p)
    out["text"] = text
    out["length"] = len(text)
    return out


async def postprocess_fetch_result(
    tool: WebFetchTool,
    url: str,
    result: Any,
    max_chars: int,
    defense: WebFetchDefenseSettings,
) -> Any:
    """Apply sanitize + pass/block policy; return vanilla-shaped JSON or minimal error."""
    policy = defense.block_policy

    if isinstance(result, list):
        if not defense.sanitize_enabled:
            return result
        tier = trust_tier_for_url(url) if defense.domain_trust_enabled else "neutral"
        combined_for_llm: list[str] = []
        for block in result:
            if (
                isinstance(block, dict)
                and block.get("type") == "text"
                and isinstance(block.get("text"), str)
                and tier != "trusted"
            ):
                sr = sanitize_web_fetch_text(block["text"], tier, max_chars)
                st = structural_outcome(sr, policy)
                if st.blocked:
                    _log_blocked(
                        url,
                        st.code,
                        structural_severity=sr.severity,
                        structural_detection_count=sr.detection_count,
                    )
                    return _blocked_tool_json(url)
                block["text"] = sr.sanitized
                combined_for_llm.append(block["text"])

        scan_cfg = defense.safety_scan
        invoked = scan_cfg.enabled and safety_classifier_invoked(
            api_key=scan_cfg.api_key,
            base_url=scan_cfg.base_url,
            model=scan_cfg.model,
        )
        if scan_cfg.enabled and not invoked:
            logger.info(
                "web_fetch_defense llm_gate_skipped url={} reason=not_invokable list=1",
                url,
            )
        if invoked and combined_for_llm:
            sample = "\n\n".join(combined_for_llm)[:CLASSIFIER_MAX_INPUT_CHARS]
            scan = await run_safety_classification(
                url=url,
                text_sample=sample,
                base_url=scan_cfg.base_url,
                model=scan_cfg.model,
                api_key=scan_cfg.api_key,
                proxy=tool.proxy,
            )
            lt = llm_classifier_outcome(scan, policy)
            if lt.blocked:
                _log_blocked(
                    url,
                    lt.code,
                    llm_verdict=str(scan.get("verdict", "")),
                    llm_severity=scan.get("severity"),
                    scan_failed=scan.get("scanFailed"),
                )
                return _blocked_tool_json(url)

        _log_allowed(url, structural_skipped=None)
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

    tier = trust_tier_for_url(url) if defense.domain_trust_enabled else "neutral"
    banner, body = _split_untrusted_banner(data["text"])

    structural_severity: int | None = None
    structural_detection_count: int | None = None
    structural_skipped: bool | None = None

    if defense.sanitize_enabled:
        sr = sanitize_web_fetch_text(body, tier, max_chars)
        body = sr.sanitized
        structural_severity = sr.severity
        structural_detection_count = sr.detection_count
        structural_skipped = sr.skipped
        st = structural_outcome(sr, policy)
        if st.blocked:
            _log_blocked(
                url,
                st.code,
                structural_severity=sr.severity,
                structural_detection_count=sr.detection_count,
            )
            return _blocked_tool_json(url)

    scan_cfg = defense.safety_scan
    llm_verdict: str | None = None
    llm_severity: int | None = None

    invoked = scan_cfg.enabled and safety_classifier_invoked(
        api_key=scan_cfg.api_key,
        base_url=scan_cfg.base_url,
        model=scan_cfg.model,
    )
    if scan_cfg.enabled and not invoked:
        logger.info(
            "web_fetch_defense llm_gate_skipped url={} reason=not_invokable",
            url,
        )
    if invoked:
        scan = await run_safety_classification(
            url=url,
            text_sample=body[:CLASSIFIER_MAX_INPUT_CHARS],
            base_url=scan_cfg.base_url,
            model=scan_cfg.model,
            api_key=scan_cfg.api_key,
            proxy=tool.proxy,
        )
        llm_verdict = str(scan.get("verdict", ""))
        sev = scan.get("severity")
        llm_severity = int(sev) if isinstance(sev, int) else None
        lt = llm_classifier_outcome(scan, policy)
        if lt.blocked:
            _log_blocked(
                url,
                lt.code,
                structural_severity=structural_severity,
                structural_detection_count=structural_detection_count,
                llm_verdict=llm_verdict,
                llm_severity=llm_severity,
                scan_failed=scan.get("scanFailed"),
            )
            return _blocked_tool_json(url)

    allowed = _allow_payload(data, banner, body)
    _log_allowed(
        url,
        structural_severity=structural_severity,
        structural_detection_count=structural_detection_count,
        structural_skipped=structural_skipped,
        llm_verdict=llm_verdict,
        llm_severity=llm_severity,
    )
    return json.dumps(allowed, ensure_ascii=False)


def make_defended_web_fetch_class(vanilla: type[WebFetchTool]) -> type[WebFetchTool]:
    """Return a subclass of ``vanilla`` ``WebFetchTool`` with defense ``execute``."""

    class _DefendedWebFetchTool(vanilla):  # type: ignore[misc,valid-type]
        async def execute(  # type: ignore[override]
            self,
            url: str,
            extractMode: str = "markdown",  # noqa: N803
            maxChars: int | None = None,  # noqa: N803
            **kwargs: Any,
        ) -> Any:
            max_chars = maxChars or self.max_chars
            is_valid, error_msg = _validate_url_safe(url)
            if not is_valid:
                return json.dumps(
                    {"error": f"URL validation failed: {error_msg}", "url": url},
                    ensure_ascii=False,
                )

            defense = load_fetch_defense_from_env()
            if defense.domain_trust_enabled and trust_tier_for_url(url) == "blocked":
                logger.warning("web_fetch_defense blocked url={} block_code=domain_blocked", url)
                return json.dumps(
                    {
                        "error": "Domain blocked by local trust tier list.",
                        "url": url,
                        "reason": "domain_blocked",
                    },
                    ensure_ascii=False,
                )

            result = await super().execute(url, extractMode, maxChars, **kwargs)
            return await postprocess_fetch_result(self, url, result, max_chars, defense)

    _DefendedWebFetchTool.__name__ = vanilla.__name__
    _DefendedWebFetchTool.__qualname__ = vanilla.__qualname__
    setattr(_DefendedWebFetchTool, "__nanobot_defended_web_fetch__", True)
    return _DefendedWebFetchTool
