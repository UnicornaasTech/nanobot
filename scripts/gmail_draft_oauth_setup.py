#!/usr/bin/env python3
"""
One-time Gmail OAuth setup for nanobot ``create_gmail_draft``.

Prompts for Desktop OAuth client ID and secret (not a credentials JSON file),
opens a local browser flow, and prints the refresh token for ``tools.gmailDraft``.

Requires: pip install -e '.[gmail]' from the repo root.

Scope: https://www.googleapis.com/auth/gmail.compose (drafts only; does not send mail).

See docs/prospr-customersupport-additions.md — Setup: Gmail, step 3.
"""

from __future__ import annotations

import getpass
import json
import sys

SCOPES = ["https://www.googleapis.com/auth/gmail.compose"]

OAUTH_CLIENT_CONFIG = {
    "installed": {
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["http://localhost"],
    }
}


def _prompt(label: str, *, secret: bool = False) -> str:
    if secret:
        value = getpass.getpass(f"{label}: ")
    else:
        value = input(f"{label}: ")
    value = value.strip()
    if not value:
        raise SystemExit(f"Error: {label} is required.")
    return value


def main() -> int:
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
    except ImportError:
        print(
            "Missing Gmail OAuth dependencies. Install from repo root:\n"
            "  pip install -e '.[gmail]'",
            file=sys.stderr,
        )
        return 1

    print("Gmail draft OAuth setup (nanobot tools.gmailDraft)\n")
    print(
        "Use a Google Cloud OAuth client of type **Desktop app** with scope "
        "gmail.compose enabled on the consent screen.\n"
    )

    client_id = _prompt("OAuth client ID")
    client_secret = _prompt("OAuth client secret", secret=True)

    client_config = {
        "installed": {
            **OAUTH_CLIENT_CONFIG["installed"],
            "client_id": client_id,
            "client_secret": client_secret,
        }
    }

    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
    print("\nOpening browser for sign-in (support mailbox that will own drafts)...")
    creds = flow.run_local_server(
        port=0,
        access_type="offline",
        prompt="consent",
    )

    refresh_token = creds.refresh_token
    if not refresh_token:
        print(
            "\nError: Google did not return a refresh token.\n"
            "Try again with prompt=consent, or revoke app access for this account at\n"
            "https://myaccount.google.com/permissions and re-run this script.",
            file=sys.stderr,
        )
        return 1

    print("\n--- Success ---\n")
    print("Add these to your secret store / environment:\n")
    print(f"GMAIL_CLIENT_ID={client_id}")
    print(f"GMAIL_CLIENT_SECRET={client_secret}")
    print(f"GMAIL_REFRESH_TOKEN={refresh_token}")
    print("\nOr in ~/.nanobot/config.json under tools.gmailDraft:\n")
    print(
        json.dumps(
            {
                "tools": {
                    "gmailDraft": {
                        "clientId": "${GMAIL_CLIENT_ID}",
                        "clientSecret": "${GMAIL_CLIENT_SECRET}",
                        "refreshToken": "${GMAIL_REFRESH_TOKEN}",
                    }
                }
            },
            indent=2,
        )
    )
    print(
        "\nNanobot does not write OAuth tokens to disk. "
        "Do not commit the refresh token to git."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
