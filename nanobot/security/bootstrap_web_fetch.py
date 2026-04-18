"""Monkey-patch ``WebFetchTool`` with defended behavior (import early via ``nanobot`` package).

Call :func:`apply` once before ``nanobot.agent.loop`` (or any consumer) binds ``WebFetchTool``.
:mod:`nanobot` ``__init__`` invokes this automatically unless disabled via env.
"""

from __future__ import annotations

_applied: bool = False


def apply() -> None:
    """Replace ``nanobot.agent.tools.web.WebFetchTool`` with a defended subclass."""
    global _applied
    if _applied:
        return
    _applied = True

    from nanobot.security.web_fetch_defense_env import defense_patch_enabled

    if not defense_patch_enabled():
        return

    import nanobot.agent.tools.web as web_mod

    vanilla = web_mod.WebFetchTool
    from nanobot.security.web_fetch_defended_tool import make_defended_web_fetch_class

    web_mod.WebFetchTool = make_defended_web_fetch_class(vanilla)
