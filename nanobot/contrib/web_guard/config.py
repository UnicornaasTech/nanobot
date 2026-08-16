"""Load ``web-fetch-guard.json`` next to ``config.json``."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pydantic
from loguru import logger
from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel

from nanobot.config.loader import get_config_path

_last_key: str | None = None
_last_mtime: float | None = None
_last_settings: WebFetchGuardSettings | None = None


def invalidate_guard_config_cache() -> None:
    """Clear cached guard settings (e.g. after tests change ``set_config_path``)."""
    global _last_key, _last_mtime, _last_settings
    _last_key = None
    _last_mtime = None
    _last_settings = None


def _guard_json_path() -> Path:
    return get_config_path().parent / "web-fetch-guard.json"


def _env_truthy_value(raw: str) -> bool:
    return raw.strip().lower() not in ("0", "false", "no", "off", "")


class _GuardBase(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class WebFetchContentGuardSettings(_GuardBase):
    """Local classifier options for post-fetch content screening."""

    enabled: bool = False
    backend: str = "cliguard"
    model_id: str = ""
    device: str = "cpu"
    threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    max_input_chars: int = Field(default=32_000, ge=256)
    fail_closed: bool = True

    def effective_device(self) -> str:
        env = os.environ.get("NANOBOT_WEB_FETCH_GUARD_DEVICE", "").strip()
        return env or self.device or "cpu"


class WebFetchGuardSettings(_GuardBase):
    """All web_fetch guard toggles (file + defaults)."""

    patch_enabled: bool = True
    content_guard: WebFetchContentGuardSettings = Field(
        default_factory=WebFetchContentGuardSettings
    )


def _load_from_file(path: Path) -> WebFetchGuardSettings:
    if not path.is_file():
        return WebFetchGuardSettings()
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning("web-fetch-guard.json: root must be an object, using defaults")
            return WebFetchGuardSettings()
        return WebFetchGuardSettings.model_validate(data)
    except (json.JSONDecodeError, OSError, pydantic.ValidationError) as e:
        logger.warning("Failed to load {}: {} — using defaults", path, e)
        return WebFetchGuardSettings()


def load_guard_config() -> WebFetchGuardSettings:
    """Return guard settings, cached until the JSON file mtime changes."""
    global _last_key, _last_mtime, _last_settings
    path = _guard_json_path()
    key = str(path.resolve())
    mtime = path.stat().st_mtime if path.is_file() else None
    if _last_key == key and _last_mtime == mtime and _last_settings is not None:
        return _last_settings
    settings = _load_from_file(path)
    _last_key = key
    _last_mtime = mtime
    _last_settings = settings
    return settings


def guard_patch_enabled() -> bool:
    """Whether bootstrap should replace ``WebFetchTool.execute``."""
    if os.environ.get("NANOBOT_WEB_FETCH_GUARD") is not None:
        return _env_truthy_value(os.environ["NANOBOT_WEB_FETCH_GUARD"])
    return load_guard_config().patch_enabled
