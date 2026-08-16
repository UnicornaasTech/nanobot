"""Monkey-patch ``WebFetchTool`` with post-fetch content guard (fork-only).

Call :func:`apply` once before ``nanobot.agent.loop`` (or any consumer) instantiates
``WebFetchTool``. :mod:`nanobot` ``__init__`` invokes this automatically unless disabled
via env.

The patch mutates ``WebFetchTool`` **in place** (replaces ``execute`` on the vanilla
class) rather than swapping the module attribute with a subclass. This is required
because ``nanobot/agent/__init__.py`` eagerly imports ``AgentLoop``, which binds
``WebFetchTool`` into its own namespace before ``apply()`` runs.
"""

from __future__ import annotations

import json
import time
from typing import Any

_applied: bool = False


def apply() -> None:
    """Replace ``WebFetchTool.execute`` with the guarded implementation."""
    global _applied
    if _applied:
        return

    from loguru import logger

    from nanobot.contrib.web_guard.config import guard_patch_enabled, load_guard_config

    if not guard_patch_enabled():
        logger.info(
            "Web fetch guard: monkey-patch skipped "
            "(patchEnabled=false in web-fetch-guard.json next to config.json, "
            "or NANOBOT_WEB_FETCH_GUARD disables it)"
        )
        _applied = True
        return

    import nanobot.agent.tools.web as web_mod
    from nanobot.agent.tools.web import _validate_url_safe
    from nanobot.contrib.web_guard.postprocess import postprocess_fetch_result

    cls = web_mod.WebFetchTool
    if getattr(cls, "__nanobot_guarded_web_fetch__", False):
        _applied = True
        return

    original_execute = cls.execute

    async def guarded_execute(  # type: ignore[override]
        self,
        url: str,
        extractMode: str = "markdown",  # noqa: N803
        maxChars: int | None = None,  # noqa: N803
        **kwargs: Any,
    ) -> Any:
        is_valid, error_msg = _validate_url_safe(url)
        if not is_valid:
            return json.dumps(
                {"error": f"URL validation failed: {error_msg}", "url": url},
                ensure_ascii=False,
            )

        settings = load_guard_config()
        page_t0 = time.perf_counter()
        result = await original_execute(self, url, extractMode, maxChars, **kwargs)
        fetch_seconds = time.perf_counter() - page_t0
        result = await postprocess_fetch_result(url, result, settings)
        logger.debug(
            "web_fetch_guard page url={} fetch_seconds={:.3f} total_seconds={:.3f}",
            url,
            fetch_seconds,
            time.perf_counter() - page_t0,
        )
        return result

    cls.execute = guarded_execute  # type: ignore[method-assign]
    setattr(cls, "__nanobot_guarded_web_fetch__", True)
    logger.info("Web fetch guard: monkey-patch active (guarded WebFetchTool.execute in place)")
    _applied = True
