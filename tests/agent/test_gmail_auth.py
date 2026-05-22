"""Gmail draft OAuth via tools.gmailDraft config (no token files)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from nanobot.agent.tools.gmail_auth import (
    GmailDraftToolConfig,
    get_gmail_service,
    reset_gmail_auth_cache,
)
from nanobot.config.schema import ToolsConfig


@pytest.fixture(autouse=True)
def _clear_gmail_cache() -> None:
    reset_gmail_auth_cache()
    yield
    reset_gmail_auth_cache()


def _configured() -> GmailDraftToolConfig:
    return GmailDraftToolConfig(
        client_id="cid",
        client_secret="csecret",
        refresh_token="rtok",
    )


def test_gmail_draft_config_is_configured() -> None:
    assert _configured().is_configured() is True
    assert GmailDraftToolConfig().is_configured() is False


def test_tools_config_gmail_draft_camel_case() -> None:
    tools = ToolsConfig.model_validate(
        {
            "gmailDraft": {
                "clientId": "a",
                "clientSecret": "b",
                "refreshToken": "c",
            }
        }
    )
    assert tools.gmail_draft.client_id == "a"
    assert tools.gmail_draft.client_secret == "b"
    assert tools.gmail_draft.refresh_token == "c"


def test_get_gmail_service_missing_config_raises() -> None:
    with pytest.raises(ValueError, match="tools.gmailDraft"):
        get_gmail_service(GmailDraftToolConfig())


def _install_fake_googleapiclient(monkeypatch: pytest.MonkeyPatch, return_value: object = "service") -> MagicMock:
    mock_build = MagicMock(return_value=return_value)
    discovery = ModuleType("googleapiclient.discovery")
    discovery.build = mock_build
    googleapiclient = ModuleType("googleapiclient")
    googleapiclient.discovery = discovery
    monkeypatch.setitem(sys.modules, "googleapiclient", googleapiclient)
    monkeypatch.setitem(sys.modules, "googleapiclient.discovery", discovery)
    return mock_build


def test_get_gmail_service_uses_cached_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    creds = MagicMock()
    creds.valid = True
    fetch_count = 0

    def fake_get_cached(_cfg: GmailDraftToolConfig) -> MagicMock:
        nonlocal fetch_count
        fetch_count += 1
        return creds

    monkeypatch.setattr(
        "nanobot.agent.tools.gmail_auth._get_cached_credentials",
        fake_get_cached,
    )
    _install_fake_googleapiclient(monkeypatch)

    cfg = _configured()
    assert get_gmail_service(cfg) == "service"
    assert get_gmail_service(cfg) == "service"
    assert fetch_count == 2


def test_get_cached_credentials_refreshes_and_reuses(monkeypatch: pytest.MonkeyPatch) -> None:
    from nanobot.agent.tools import gmail_auth as ga

    creds = MagicMock()
    creds.valid = False
    creds.refresh_token = "rtok"

    build_count = 0

    def fake_from_config(_cfg: GmailDraftToolConfig) -> MagicMock:
        nonlocal build_count
        build_count += 1
        return creds

    request_mod = ModuleType("google.auth.transport.requests")
    request_mod.Request = MagicMock
    auth_transport = ModuleType("google.auth.transport")
    auth_transport.requests = request_mod
    google_auth = ModuleType("google.auth")
    google_auth.transport = auth_transport
    google = ModuleType("google")
    google.auth = google_auth
    monkeypatch.setitem(sys.modules, "google", google)
    monkeypatch.setitem(sys.modules, "google.auth", google_auth)
    monkeypatch.setitem(sys.modules, "google.auth.transport", auth_transport)
    monkeypatch.setitem(sys.modules, "google.auth.transport.requests", request_mod)

    monkeypatch.setattr(ga, "_credentials_from_config", fake_from_config)

    cfg = _configured()
    assert ga._get_cached_credentials(cfg) is creds
    creds.refresh.assert_called_once()
    creds.valid = True
    assert ga._get_cached_credentials(cfg) is creds
    assert build_count == 1


def test_get_gmail_service_does_not_write_token_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token_path = tmp_path / "gmail_token.json"
    creds_path = tmp_path / "gmail_credentials.json"

    creds = MagicMock()
    creds.valid = True
    monkeypatch.setattr(
        "nanobot.agent.tools.gmail_auth._get_cached_credentials",
        lambda _cfg: creds,
    )
    _install_fake_googleapiclient(monkeypatch, "svc")

    get_gmail_service(_configured())

    assert not token_path.exists()
    assert not creds_path.exists()


def test_cache_invalidates_when_config_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    from nanobot.agent.tools import gmail_auth as ga

    calls: list[str] = []

    def fake_from_config(cfg: GmailDraftToolConfig) -> MagicMock:
        c = MagicMock()
        c.valid = True
        calls.append(cfg.refresh_token)
        return c

    monkeypatch.setattr(ga, "_credentials_from_config", fake_from_config)

    ga._get_cached_credentials(_configured())
    ga._get_cached_credentials(
        GmailDraftToolConfig(
            client_id="cid",
            client_secret="csecret",
            refresh_token="other",
        )
    )
    assert calls == ["rtok", "other"]
