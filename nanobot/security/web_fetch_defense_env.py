"""Web fetch defense settings loaded from a JSON file next to ``config.json``.

The file path is ``<directory of config.json>/web-fetch-defense.json``. If the file is
missing, defaults match the previous in-tree behavior (patch on, sanitize on, domain
trust on, safety scan off).

Example ``web-fetch-defense.json``::

    {
      "patchEnabled": true,
      "sanitizeEnabled": true,
      "domainTrustEnabled": true,
      "blockPolicy": {
        "structuralBlockMinSeverity": 9,
        "structuralBlockMinDetectionCount": 3,
        "suspiciousBlockMinSeverity": 4
      },
      "safetyScan": {
        "enabled": false,
        "baseUrl": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "apiKey": ""
      }
    }

``blockPolicy`` thresholds control pass vs withhold for defended fetches; see
:mod:`nanobot.security.web_fetch_block_policy` for the exact rules.

``apiKey`` may be left empty; :mod:`nanobot.security.web_fetch_safety_scan` still reads
``NANOBOT_WEB_FETCH_SAFETY_API_KEY`` / ``OPENAI_API_KEY`` when calling the classifier.

Optional env override: if ``NANOBOT_WEB_FETCH_DEFENSE`` is set in the environment, it
overrides ``patchEnabled`` from the file (so you can disable the monkey-patch in
containers without editing the JSON).
"""

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
_last_settings: "WebFetchDefenseSettings | None" = None


def invalidate_fetch_defense_config_cache() -> None:
    """Clear cached defense settings (e.g. after tests change ``set_config_path``)."""
    global _last_key, _last_mtime, _last_settings
    _last_key = None
    _last_mtime = None
    _last_settings = None


def _defense_json_path() -> Path:
    return get_config_path().parent / "web-fetch-defense.json"


def _env_truthy_value(raw: str) -> bool:
    return raw.strip().lower() not in ("0", "false", "no", "off", "")


class _DefenseBase(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class WebFetchSafetyScanSettings(_DefenseBase):
    """Stage 3 classifier options (OpenAI-compatible chat completions)."""

    enabled: bool = False
    base_url: str = ""
    model: str = ""
    api_key: str = ""


class WebFetchBlockPolicySettings(_DefenseBase):
    """Thresholds for withheld vs allowed fetch content (see ``web_fetch_block_policy``)."""

    structural_block_min_severity: int = Field(default=9, ge=1)
    structural_block_min_detection_count: int = Field(default=3, ge=1)
    suspicious_block_min_severity: int = Field(default=4, ge=1, le=5)


class WebFetchDefenseSettings(_DefenseBase):
    """All web_fetch defense toggles (file + defaults)."""

    patch_enabled: bool = True
    sanitize_enabled: bool = True
    domain_trust_enabled: bool = True
    block_policy: WebFetchBlockPolicySettings = Field(default_factory=WebFetchBlockPolicySettings)
    safety_scan: WebFetchSafetyScanSettings = Field(default_factory=WebFetchSafetyScanSettings)


def _load_from_file(path: Path) -> WebFetchDefenseSettings:
    if not path.is_file():
        return WebFetchDefenseSettings()
    try:
        with path.open(encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            logger.warning("web-fetch-defense.json: root must be an object, using defaults")
            return WebFetchDefenseSettings()
        return WebFetchDefenseSettings.model_validate(data)
    except (json.JSONDecodeError, OSError, pydantic.ValidationError) as e:
        logger.warning("Failed to load {}: {} — using defaults", path, e)
        return WebFetchDefenseSettings()


def load_fetch_defense_config() -> WebFetchDefenseSettings:
    """Return defense settings, cached until the JSON file mtime changes."""
    global _last_key, _last_mtime, _last_settings
    path = _defense_json_path()
    key = str(path.resolve())
    mtime = path.stat().st_mtime if path.is_file() else None
    if _last_key == key and _last_mtime == mtime and _last_settings is not None:
        return _last_settings
    settings = _load_from_file(path)
    _last_key = key
    _last_mtime = mtime
    _last_settings = settings
    return settings


def load_fetch_defense_from_env() -> WebFetchDefenseSettings:
    """Alias for :func:`load_fetch_defense_config` (backward compatible name)."""
    return load_fetch_defense_config()


def defense_patch_enabled() -> bool:
    """Whether bootstrap should replace ``WebFetchTool``."""
    if os.environ.get("NANOBOT_WEB_FETCH_DEFENSE") is not None:
        return _env_truthy_value(os.environ["NANOBOT_WEB_FETCH_DEFENSE"])
    return load_fetch_defense_config().patch_enabled
