"""
Gmail OAuth2 helper. Call get_gmail_service() to obtain an authorized API
Resource object. Stores token in ~/.nanobot/gmail_token.json.

Google documentation:

- Gmail API overview: https://developers.google.com/workspace/gmail/api/guides
- OAuth scopes (``gmail.compose`` creates drafts; does not send):
  https://developers.google.com/workspace/gmail/api/auth/scopes

Google client libraries are imported lazily so the rest of nanobot works
without optional ``[gmail]`` dependencies installed.
"""

from __future__ import annotations

from pathlib import Path

SCOPES = ["https://www.googleapis.com/auth/gmail.compose"]
TOKEN_PATH = Path.home() / ".nanobot" / "gmail_token.json"
CREDS_PATH = Path.home() / ".nanobot" / "gmail_credentials.json"


def get_gmail_service():
    """Return a Gmail API v1 service client (lazy-imports optional dependencies)."""
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    creds = None
    if TOKEN_PATH.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not CREDS_PATH.exists():
                raise FileNotFoundError(
                    f"Missing Gmail OAuth client file at {CREDS_PATH}. "
                    "Download credentials.json from Google Cloud Console and save it there."
                )
            flow = InstalledAppFlow.from_client_secrets_file(str(CREDS_PATH), SCOPES)
            creds = flow.run_local_server(port=0)
        TOKEN_PATH.write_text(creds.to_json())
    return build("gmail", "v1", credentials=creds)
