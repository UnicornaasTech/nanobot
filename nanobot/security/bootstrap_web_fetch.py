"""Monkey-patch ``WebFetchTool`` with defended behavior (import early via ``nanobot`` package).

Call :func:`apply` once before ``nanobot.agent.loop`` (or any consumer) instantiates
``WebFetchTool``. :mod:`nanobot` ``__init__`` invokes this automatically unless disabled
via env.

The patch mutates ``WebFetchTool`` **in place** (replaces ``execute`` on the vanilla
class) rather than swapping the module attribute with a subclass. This is required
because ``nanobot/agent/__init__.py`` eagerly imports ``AgentLoop``, which binds
``WebFetchTool`` into its own namespace before ``apply()`` runs. An in-place patch
is visible through those existing references; an attribute swap is not.
"""

from __future__ import annotations

import json
import time
from typing import Any

_applied: bool = False


def apply() -> None:
    """Replace ``WebFetchTool.execute`` with the defended implementation."""
    global _applied
    if _applied:
        return

    from loguru import logger
    from nanobot.security.web_fetch_defense_env import defense_patch_enabled

    if not defense_patch_enabled():
        logger.info(
            "Web fetch defense: monkey-patch skipped "
            "(patchEnabled=false in web-fetch-defense.json next to config.json, "
            "or NANOBOT_WEB_FETCH_DEFENSE disables it)"
        )
        _applied = True
        return

    import nanobot.agent.tools.web as web_mod
    from nanobot.agent.tools.web import _validate_url_safe
    from nanobot.security.web_fetch_defended_tool import postprocess_fetch_result
    from nanobot.security.web_fetch_defense_env import load_fetch_defense_from_env
    from nanobot.security.web_fetch_domain_trust import trust_tier_for_url

    cls = web_mod.WebFetchTool
    if getattr(cls, "__nanobot_defended_web_fetch__", False):
        _applied = True
        return

    original_execute = cls.execute

    async def defended_execute(  # type: ignore[override]
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

        fetch_t0 = time.perf_counter()
        result = await original_execute(self, url, extractMode, maxChars, **kwargs)
        logger.debug(
            "web_fetch_defense fetch url={} seconds={:.3f}",
            url,
            time.perf_counter() - fetch_t0,
        )
        return await postprocess_fetch_result(self, url, result, max_chars, defense)

    cls.execute = defended_execute  # type: ignore[method-assign]
    setattr(cls, "__nanobot_defended_web_fetch__", True)
    logger.info(
        "Web fetch defense: monkey-patch active (defended WebFetchTool.execute in place)"
    )
    _applied = True
