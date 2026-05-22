"""
Gmail OAuth2 helper for the create_gmail_draft tool.

Credentials come from ``tools.gmailDraft`` in config (clientId, clientSecret,
refreshToken). Access tokens are cached in memory only; nothing is written to disk.

Google documentation:

- Gmail API overview: https://developers.google.com/workspace/gmail/api/guides
- OAuth scopes (``gmail.compose`` drafts; ``gmail.readonly`` resolves reply threads):
  https://developers.google.com/workspace/gmail/api/auth/scopes

Google client libraries are imported lazily so the rest of nanobot works
without optional ``[gmail]`` dependencies installed.
"""

from __future__ import annotations

from typing import Any

from nanobot.config.schema import Base

SCOPES = [
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.readonly",
]
TOKEN_URI = "https://oauth2.googleapis.com/token"

_cached_creds: Any = None
_cached_config_key: tuple[str, str, str] | None = None


class GmailDraftToolConfig(Base):
    """OAuth settings for ``create_gmail_draft`` (config key ``tools.gmailDraft``)."""

    client_id: str = ""
    client_secret: str = ""
    refresh_token: str = ""

    def is_configured(self) -> bool:
        return bool(
            (self.client_id or "").strip()
            and (self.client_secret or "").strip()
            and (self.refresh_token or "").strip()
        )

    def config_key(self) -> tuple[str, str, str]:
        return (self.client_id.strip(), self.client_secret.strip(), self.refresh_token.strip())


def _validate_gmail_draft_config(gmail_draft: GmailDraftToolConfig) -> None:
    if gmail_draft.is_configured():
        return
    missing = []
    if not (gmail_draft.client_id or "").strip():
        missing.append("clientId")
    if not (gmail_draft.client_secret or "").strip():
        missing.append("clientSecret")
    if not (gmail_draft.refresh_token or "").strip():
        missing.append("refreshToken")
    raise ValueError(
        "Gmail draft OAuth is not configured. Set tools.gmailDraft "
        f"({', '.join(missing)}) in ~/.nanobot/config.json "
        "(values may use ${ENV_VAR} interpolation)."
    )


def _credentials_from_config(gmail_draft: GmailDraftToolConfig) -> Any:
    from google.oauth2.credentials import Credentials

    return Credentials(
        token=None,
        refresh_token=gmail_draft.refresh_token.strip(),
        token_uri=TOKEN_URI,
        client_id=gmail_draft.client_id.strip(),
        client_secret=gmail_draft.client_secret.strip(),
        scopes=SCOPES,
    )


def _get_cached_credentials(gmail_draft: GmailDraftToolConfig) -> Any:
    global _cached_creds, _cached_config_key

    key = gmail_draft.config_key()
    creds = _cached_creds if _cached_config_key == key else None

    if creds is None or not creds.valid:
        if creds is None or not creds.refresh_token:
            creds = _credentials_from_config(gmail_draft)
        if not creds.valid:
            from google.auth.transport.requests import Request

            creds.refresh(Request())
        _cached_creds = creds
        _cached_config_key = key

    return _cached_creds


def get_gmail_service(gmail_draft: GmailDraftToolConfig) -> Any:
    """Return a Gmail API v1 service client (lazy-imports optional dependencies)."""
    _validate_gmail_draft_config(gmail_draft)
    from googleapiclient.discovery import build

    creds = _get_cached_credentials(gmail_draft)
    return build("gmail", "v1", credentials=creds)


def reset_gmail_auth_cache() -> None:
    """Clear in-memory OAuth cache (for tests)."""
    global _cached_creds, _cached_config_key
    _cached_creds = None
    _cached_config_key = None
