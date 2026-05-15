# Nanobot Implementation Instructions
## Features: Gmail Draft Tool + Instagram DM Channel

These instructions are for a coding agent working on a **source-installed nanobot** (`git clone https://github.com/HKUDS/nanobot`). Read the existing codebase before writing any code — specifically study `nanobot/channels/email.py`, `nanobot/channels/slack.py`, and `nanobot/tools/` to understand the patterns before implementing anything.

---

## Part 1 — Gmail "Draft Only" Tool

### Goal
Replace nanobot's email send capability with a tool that **creates a Gmail Draft** instead of sending. The send path must be **removed at the code level**, not just suppressed by an instruction.

### Prerequisites
- A Google Cloud project with the Gmail API enabled
- OAuth 2.0 credentials (`credentials.json`) with scope `https://www.googleapis.com/auth/gmail.compose`
- `pip install --upgrade google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client`

### Step 1 — Disable SMTP send in the email channel

Open `nanobot/channels/email.py`. Find the method responsible for sending replies (likely named `send_message`, `reply`, or `_send`). **Delete the method body and replace it with a hard raise:**

```python
def send_message(self, *args, **kwargs):
    raise NotImplementedError(
        "Email sending is disabled by policy. Use the create_gmail_draft tool instead."
    )
```

Also find any call sites within the same file that invoke `smtplib` or call this method and remove or guard them. The goal: no code path should be able to reach an SMTP `sendmail()` call.

Set `autoReplyEnabled: false` in `~/.nanobot/config.json` under the email channel config as a second layer, but do NOT rely on this alone — the code-level block above is the enforceable constraint.

### Step 2 — Create the Gmail OAuth helper

Create `nanobot/tools/gmail_auth.py`:

```python
"""
Gmail OAuth2 helper. Call get_gmail_service() to obtain an authorized
Resource object. Stores token in ~/.nanobot/gmail_token.json.
"""
import os
from pathlib import Path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.compose"]
TOKEN_PATH = Path.home() / ".nanobot" / "gmail_token.json"
CREDS_PATH = Path.home() / ".nanobot" / "gmail_credentials.json"


def get_gmail_service():
    creds = None
    if TOKEN_PATH.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(str(CREDS_PATH), SCOPES)
            creds = flow.run_local_server(port=0)
        TOKEN_PATH.write_text(creds.to_json())
    return build("gmail", "v1", credentials=creds)
```

Place your downloaded `credentials.json` at `~/.nanobot/gmail_credentials.json`.

Run `python -c "from nanobot.tools.gmail_auth import get_gmail_service; get_gmail_service()"` once manually to complete the OAuth browser flow and save the token. After that, nanobot can run headlessly.

### Step 3 — Create the draft tool

Create `nanobot/tools/create_gmail_draft.py`:

```python
"""
Tool: create_gmail_draft
Creates a Gmail draft as a reply to an existing message thread.
NEVER sends. Raises on any attempt to call the actual send endpoint.
"""
import base64
import email as email_lib
from email.mime.text import MIMEText
from nanobot.tools.gmail_auth import get_gmail_service


def create_gmail_draft(
    to: str,
    subject: str,
    body: str,
    thread_id: str | None = None,
    in_reply_to: str | None = None,
    references: str | None = None,
) -> dict:
    """
    Creates a draft reply in Gmail. Does NOT send.

    Args:
        to: Recipient email address.
        subject: Email subject. Prefix with 'Re: ' if replying.
        body: Plain-text body of the draft.
        thread_id: Gmail thread ID to attach the draft to (for reply threading).
        in_reply_to: Message-ID header of the message being replied to.
        references: References header chain for threading.

    Returns:
        dict with 'draft_id', 'thread_id', and 'gmail_url' for the created draft.

    Raises:
        RuntimeError: Always raised if this function is called with send=True
                      (parameter does not exist — guard against future changes).
    """
    # Hard guard — this function must never send under any circumstances
    if "send" in create_gmail_draft.__code__.co_varnames:
        raise RuntimeError("Policy violation: send parameter must never be added to this tool.")

    msg = MIMEText(body, "plain")
    msg["To"] = to
    msg["Subject"] = subject
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if references:
        msg["References"] = references

    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    body_payload: dict = {"message": {"raw": raw}}
    if thread_id:
        body_payload["message"]["threadId"] = thread_id

    service = get_gmail_service()
    draft = service.users().drafts().create(userId="me", body=body_payload).execute()

    draft_id = draft["id"]
    return {
        "draft_id": draft_id,
        "thread_id": draft.get("message", {}).get("threadId"),
        "gmail_url": f"https://mail.google.com/mail/u/0/#drafts/{draft_id}",
        "status": "draft_created_not_sent",
    }
```

### Step 4 — Register the tool with nanobot

Open nanobot's tool registry (likely `nanobot/tools/__init__.py` or `nanobot/tools/registry.py`). Register `create_gmail_draft` following the same pattern used for existing tools (web search, file tools, etc.).

In the tool's description string that is shown to the LLM, include: *"Creates a Gmail draft for human review. NEVER sends the email. Always use this instead of any send operation."*

Also ensure the tool is listed in the agent's available tools in `AGENTS.md` in the workspace, e.g.:
```
## Email
- Use `create_gmail_draft` to draft replies to support emails.
- NEVER attempt to send email directly. There is no send tool.
```

### Step 5 — Configure the email channel (read-only)

In `~/.nanobot/config.json`:

```json
{
  "channels": {
    "email": {
      "enabled": true,
      "consentGranted": true,
      "autoReplyEnabled": false,
      "imapHost": "imap.gmail.com",
      "imapPort": 993,
      "imapUsername": "support@yourcompany.com",
      "imapPassword": "your-google-app-password",
      "allowFrom": ["*"]
    }
  }
}
```

Note: No `smtpHost`, `smtpPort`, or `smtpPassword` — omitting SMTP config entirely is a third layer of protection.

### Verification

Write a test `tests/test_email_draft.py`:
```python
from nanobot.channels.email import EmailChannel
import pytest

def test_send_is_disabled():
    ch = EmailChannel.__new__(EmailChannel)
    with pytest.raises(NotImplementedError):
        ch.send_message("test@example.com", "Test", "Body")

def test_draft_creates_not_sends(monkeypatch):
    from nanobot.tools.create_gmail_draft import create_gmail_draft
    # Monkeypatch get_gmail_service to return a mock
    # Assert result dict contains 'status': 'draft_created_not_sent'
    # Assert no HTTP call is made to /send endpoint
    pass  # implement with unittest.mock
```

---

## Part 2 — Instagram DM Channel

### Goal
Build a new nanobot channel that:
1. Receives incoming Instagram DMs via a Meta webhook
2. Passes them into nanobot's agent loop for reply drafting
3. Posts the drafted reply to a Slack `#instagram-drafts` channel with **Send**, **Edit & Send**, and **Discard** buttons
4. On **Send**: posts the draft as-is to Instagram via the API
5. On **Edit & Send**: opens a Slack modal where the human edits the text, then sends on confirm
6. On **Discard**: marks the Slack message as discarded, does nothing on Instagram
7. The nanobot agent itself **never calls the Instagram send endpoint** — only the human-triggered Slack action does

### Architecture overview

```
Instagram user sends DM
        ↓
Meta webhook → POST /webhook/instagram  (your server, port 5005)
        ↓
InstagramChannel._handle_payload()
        ↓
nanobot agent loop → drafts reply text
        ↓
post_draft_to_slack() → Slack message with [Send] [Edit & Send] [Discard]
        ↓
Human clicks a button
        ↓
Slack interactivity → POST /slack/actions  (same server, port 5005)
        ↓
_handle_slack_action():
  • Send       → _send_instagram_message() → Meta API → update Slack msg "✅ Sent"
  • Edit&Send  → open Slack modal → on submit → _send_instagram_message() → "✅ Sent"
  • Discard    → update Slack msg "🗑 Discarded"
```

The agent's `send_message()` method still raises unconditionally. Only `_send_instagram_message()` — which is only reachable from a human Slack action — calls the Meta API.

### Prerequisites
- Instagram Business or Creator account linked to a Facebook Page
- Meta Developer App with `instagram_manage_messages` and `pages_messaging` permissions approved
- App must pass Meta's Business Verification and App Review for messaging
- A public HTTPS endpoint on your server (or use ngrok for development)
- Your existing Slack bot token, the target channel ID for `#instagram-drafts`, and Slack Interactivity enabled in your Slack App settings with Request URL pointing to `https://your-server.com/slack/actions`
- `pip install flask requests`

### Step 1 — Study the base channel interface

Before writing any code, read `nanobot/channels/base.py` in full. Implement `InstagramChannel` to satisfy the same interface. Key methods: `start()`, `stop()`, and the incoming message dispatch pattern (look for `on_message`, `dispatch`, or a queue-based approach in `slack.py` or `telegram.py`).

### Step 2 — Slack App configuration

Before writing code, do this in the Slack App dashboard:

1. Under **Interactivity & Shortcuts**, enable Interactivity and set **Request URL** to `https://your-server.com/slack/actions`
2. Under **OAuth & Permissions**, ensure the bot token has scopes: `chat:write`, `chat:update`, `views.open`
3. Reinstall the app to your workspace after changing scopes

### Step 3 — Create the channel file

Create `nanobot/channels/instagram.py`:

```python
"""
Instagram DM channel for nanobot.

Incoming DMs → agent drafts reply → Slack message with action buttons.
A human clicks Send / Edit & Send / Discard in Slack.
Only human-triggered Slack actions call the Instagram send API.
The agent's send_message() raises unconditionally — by design.
"""
import hashlib
import hmac
import json
import logging
import threading
from typing import Callable

import requests
from flask import Flask, request, jsonify

from nanobot.channels.base import BaseChannel  # adjust to match actual base class

logger = logging.getLogger(__name__)

# Action IDs — used in Slack block payloads and modal callbacks
ACTION_SEND = "ig_draft_send"
ACTION_EDIT_SEND = "ig_draft_edit_send"
ACTION_DISCARD = "ig_draft_discard"
CALLBACK_EDIT_MODAL = "ig_edit_modal_submit"


class InstagramChannel(BaseChannel):
    """
    Nanobot channel for Instagram DMs.

    Agent writes drafts; humans approve/edit/discard via Slack buttons.
    """

    CHANNEL_NAME = "instagram"

    def __init__(self, config: dict, on_message: Callable):
        """
        config keys:
            app_secret           (str)  Meta app secret for webhook signature verification
            verify_token         (str)  Webhook verify token set in Meta dashboard
            page_access_token    (str)  Page access token with instagram_manage_messages
            ig_user_id           (str)  Your Instagram-scoped user ID
            slack_bot_token      (str)  Slack bot token (chat:write, chat:update, views.open)
            slack_draft_channel  (str)  Slack channel ID for draft review, e.g. C0XXXXXXXXX
            slack_signing_secret (str)  Slack signing secret for action request verification
            webhook_host         (str)  Flask bind host, default "0.0.0.0"
            webhook_port         (int)  Flask bind port, default 5005
        """
        self.config = config
        self.on_message = on_message
        self.app = Flask(__name__)
        self._register_routes()
        self._server_thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Route registration
    # ------------------------------------------------------------------

    def _register_routes(self):

        @self.app.route("/webhook/instagram", methods=["GET"])
        def ig_verify():
            """Meta webhook verification handshake."""
            mode = request.args.get("hub.mode")
            token = request.args.get("hub.verify_token")
            challenge = request.args.get("hub.challenge")
            if mode == "subscribe" and token == self.config["verify_token"]:
                logger.info("Instagram webhook verified.")
                return challenge, 200
            return "Forbidden", 403

        @self.app.route("/webhook/instagram", methods=["POST"])
        def ig_receive():
            """Receive incoming DM events from Meta."""
            if not self._verify_meta_signature(request):
                return "Unauthorized", 401
            payload = request.get_json(force=True)
            self._handle_ig_payload(payload)
            return jsonify({"status": "ok"}), 200

        @self.app.route("/slack/actions", methods=["POST"])
        def slack_actions():
            """Receive button clicks and modal submissions from Slack."""
            if not self._verify_slack_signature(request):
                return "Unauthorized", 401
            payload = json.loads(request.form["payload"])
            self._handle_slack_action(payload)
            # Slack requires a 200 within 3 seconds; heavy work should be threaded
            return "", 200

    # ------------------------------------------------------------------
    # Signature verification
    # ------------------------------------------------------------------

    def _verify_meta_signature(self, req) -> bool:
        sig_header = req.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            self.config["app_secret"].encode(), req.data, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig_header, expected):
            logger.warning("Meta webhook signature mismatch — rejected.")
            return False
        return True

    def _verify_slack_signature(self, req) -> bool:
        """Verify Slack's request signature (v0 scheme)."""
        signing_secret = self.config["slack_signing_secret"].encode()
        timestamp = req.headers.get("X-Slack-Request-Timestamp", "")
        slack_sig = req.headers.get("X-Slack-Signature", "")
        base = f"v0:{timestamp}:{req.get_data(as_text=True)}"
        expected = "v0=" + hmac.new(signing_secret, base.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(slack_sig, expected):
            logger.warning("Slack action signature mismatch — rejected.")
            return False
        return True

    # ------------------------------------------------------------------
    # Instagram webhook handling
    # ------------------------------------------------------------------

    def _handle_ig_payload(self, payload: dict):
        for entry in payload.get("entry", []):
            for messaging in entry.get("messaging", []):
                sender_id = messaging.get("sender", {}).get("id")
                text = messaging.get("message", {}).get("text")
                if not text or not sender_id:
                    continue
                logger.info(f"Instagram DM from {sender_id}: {text[:80]}")
                self.on_message(
                    channel=self.CHANNEL_NAME,
                    sender_id=sender_id,
                    text=text,
                    metadata={"platform": "instagram", "raw": messaging},
                )

    # ------------------------------------------------------------------
    # Slack draft posting
    # ------------------------------------------------------------------

    def post_draft_to_slack(
        self,
        sender_id: str,
        original_message: str,
        drafted_reply: str,
        sender_display_name: str = "",
    ):
        """
        Post an agent-drafted reply to Slack with Send / Edit & Send / Discard buttons.
        This is the only method the agent loop calls. It does NOT touch Instagram.
        """
        slack_token = self.config["slack_bot_token"]
        channel = self.config["slack_draft_channel"]
        name_str = f" ({sender_display_name})" if sender_display_name else ""

        # Encode context needed by action handler into button values
        # Keep it compact — Slack's action value limit is 2000 chars
        ctx = json.dumps({"sender_id": sender_id, "original": original_message[:300]})

        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f":instagram: *Instagram DM — review required*\n"
                        f"*From:* `{sender_id}`{name_str}\n"
                        f"*Customer:* {original_message}"
                    ),
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Agent draft:*\n{drafted_reply}",
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Send"},
                        "style": "primary",
                        "action_id": ACTION_SEND,
                        # value carries sender_id + draft so the action handler is self-contained
                        "value": json.dumps({
                            "sender_id": sender_id,
                            "draft": drafted_reply,
                            "original": original_message[:300],
                        }),
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✏️ Edit & Send"},
                        "action_id": ACTION_EDIT_SEND,
                        "value": json.dumps({
                            "sender_id": sender_id,
                            "draft": drafted_reply,
                            "original": original_message[:300],
                        }),
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "🗑 Discard"},
                        "style": "danger",
                        "action_id": ACTION_DISCARD,
                        "value": json.dumps({
                            "sender_id": sender_id,
                            "original": original_message[:300],
                        }),
                    },
                ],
            },
        ]

        resp = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {slack_token}"},
            json={
                "channel": channel,
                "blocks": blocks,
                "text": f"Instagram DM draft for {sender_id}",
            },
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        if not data.get("ok"):
            logger.error(f"Slack post failed: {data.get('error')}")
        else:
            logger.info(f"Draft posted to Slack for {sender_id}")

    # ------------------------------------------------------------------
    # Slack action handling
    # ------------------------------------------------------------------

    def _handle_slack_action(self, payload: dict):
        """Dispatch Send / Edit & Send / Discard button clicks and modal submissions."""
        ptype = payload.get("type")

        if ptype == "block_actions":
            for action in payload.get("actions", []):
                action_id = action.get("action_id")
                value = json.loads(action.get("value", "{}"))
                channel = payload["channel"]["id"]
                ts = payload["message"]["ts"]
                trigger_id = payload.get("trigger_id")

                if action_id == ACTION_SEND:
                    threading.Thread(
                        target=self._do_send,
                        args=(value["sender_id"], value["draft"], channel, ts),
                        daemon=True,
                    ).start()

                elif action_id == ACTION_EDIT_SEND:
                    self._open_edit_modal(
                        trigger_id=trigger_id,
                        sender_id=value["sender_id"],
                        draft=value["draft"],
                        original=value.get("original", ""),
                        slack_channel=channel,
                        slack_ts=ts,
                    )

                elif action_id == ACTION_DISCARD:
                    threading.Thread(
                        target=self._do_discard,
                        args=(value["sender_id"], value.get("original", ""), channel, ts),
                        daemon=True,
                    ).start()

        elif ptype == "view_submission":
            cb = payload.get("view", {}).get("callback_id")
            if cb == CALLBACK_EDIT_MODAL:
                self._handle_edit_modal_submit(payload)

    def _open_edit_modal(
        self,
        trigger_id: str,
        sender_id: str,
        draft: str,
        original: str,
        slack_channel: str,
        slack_ts: str,
    ):
        """Open a Slack modal so the human can edit the draft before sending."""
        # Pass channel+ts through private_metadata so the submit handler can update the message
        private_metadata = json.dumps({
            "sender_id": sender_id,
            "slack_channel": slack_channel,
            "slack_ts": slack_ts,
            "original": original,
        })
        modal = {
            "type": "modal",
            "callback_id": CALLBACK_EDIT_MODAL,
            "private_metadata": private_metadata,
            "title": {"type": "plain_text", "text": "Edit Instagram Reply"},
            "submit": {"type": "plain_text", "text": "Send"},
            "close": {"type": "plain_text", "text": "Cancel"},
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Customer message:*\n{original}",
                    },
                },
                {
                    "type": "input",
                    "block_id": "edited_reply_block",
                    "label": {"type": "plain_text", "text": "Your reply"},
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "edited_reply_input",
                        "multiline": True,
                        "initial_value": draft,
                    },
                },
            ],
        }
        resp = requests.post(
            "https://slack.com/api/views.open",
            headers={"Authorization": f"Bearer {self.config['slack_bot_token']}"},
            json={"trigger_id": trigger_id, "view": modal},
            timeout=10,
        )
        data = resp.json()
        if not data.get("ok"):
            logger.error(f"Failed to open edit modal: {data.get('error')}")

    def _handle_edit_modal_submit(self, payload: dict):
        """Called when the human submits the edit modal."""
        meta = json.loads(payload["view"]["private_metadata"])
        edited_text = (
            payload["view"]["state"]["values"]
            ["edited_reply_block"]["edited_reply_input"]["value"]
        )
        threading.Thread(
            target=self._do_send,
            args=(meta["sender_id"], edited_text, meta["slack_channel"], meta["slack_ts"]),
            daemon=True,
        ).start()

    # ------------------------------------------------------------------
    # Instagram send (only reachable from human Slack action)
    # ------------------------------------------------------------------

    def _send_instagram_message(self, recipient_id: str, text: str) -> bool:
        """
        Send a message to an Instagram user via the Meta Messenger API.
        PRIVATE — only called from _do_send(), which is only triggered by a human
        clicking Send in Slack. Never called by the agent loop.
        """
        url = "https://graph.facebook.com/v19.0/me/messages"
        payload = {
            "recipient": {"id": recipient_id},
            "message": {"text": text},
            "messaging_type": "RESPONSE",
        }
        resp = requests.post(
            url,
            params={"access_token": self.config["page_access_token"]},
            json=payload,
            timeout=10,
        )
        if resp.status_code != 200:
            logger.error(f"Instagram send failed: {resp.status_code} {resp.text}")
            return False
        logger.info(f"Instagram message sent to {recipient_id}")
        return True

    def _do_send(self, sender_id: str, text: str, slack_channel: str, slack_ts: str):
        """Send the reply to Instagram and update the Slack message to reflect the outcome."""
        ok = self._send_instagram_message(sender_id, text)
        status_text = "✅ *Sent* by <@{who}>" if ok else "❌ *Send failed* — check logs"
        self._update_slack_message(
            channel=slack_channel,
            ts=slack_ts,
            status=f"✅ Sent to `{sender_id}`" if ok else "❌ Send failed — check server logs",
            sent_text=text if ok else None,
        )

    def _do_discard(self, sender_id: str, original: str, slack_channel: str, slack_ts: str):
        self._update_slack_message(
            channel=slack_channel,
            ts=slack_ts,
            status=f"🗑 Discarded — no reply sent to `{sender_id}`",
        )

    def _update_slack_message(
        self,
        channel: str,
        ts: str,
        status: str,
        sent_text: str | None = None,
    ):
        """Replace the action buttons with a status line (prevents double-clicks)."""
        blocks = [
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": status}],
            }
        ]
        if sent_text:
            blocks.insert(0, {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Sent reply:*\n{sent_text}"},
            })
        requests.post(
            "https://slack.com/api/chat.update",
            headers={"Authorization": f"Bearer {self.config['slack_bot_token']}"},
            json={"channel": channel, "ts": ts, "blocks": blocks, "text": status},
            timeout=10,
        )

    # ------------------------------------------------------------------
    # BaseChannel interface
    # ------------------------------------------------------------------

    def start(self):
        host = self.config.get("webhook_host", "0.0.0.0")
        port = self.config.get("webhook_port", 5005)
        self._server_thread = threading.Thread(
            target=lambda: self.app.run(host=host, port=port, use_reloader=False),
            daemon=True,
        )
        self._server_thread.start()
        logger.info(f"Instagram channel listening on {host}:{port}")

    def stop(self):
        logger.info("Instagram channel stopping.")

    def send_message(self, *args, **kwargs):
        """
        Unconditionally disabled for the agent.
        Only _send_instagram_message() sends, and only from human Slack actions.
        """
        raise NotImplementedError(
            "Direct Instagram send is disabled. "
            "Drafts go to Slack; humans send via the Approve button."
        )
```

### Step 4 — Wire the draft posting into the agent loop

After nanobot's agent produces a reply for an Instagram session, it needs to call `post_draft_to_slack` instead of sending. Find where nanobot dispatches outgoing messages back to the originating channel (likely in `nanobot/agent/loop.py` or `nanobot/session/manager.py`).

Add a branch for the `instagram` channel:

```python
if message.channel == "instagram":
    instagram_channel.post_draft_to_slack(
        sender_id=message.sender_id,
        original_message=message.original_text,
        drafted_reply=agent_reply,
    )
else:
    channel.send_message(agent_reply)
```

The exact hook point depends on nanobot's internal dispatch pattern — read the code before implementing.

### Step 5 — Register the channel

Open `nanobot/channels/__init__.py` or wherever channels are registered/discovered. Add `InstagramChannel` following the same pattern as `SlackChannel` or `EmailChannel`.

### Step 6 — Add config schema

Open `nanobot/config/schema.py`. Add an `InstagramChannelConfig` model following the pattern of `EmailChannelConfig` or `SlackChannelConfig`, with the fields from the constructor docstring above. Add it to the top-level `ChannelsConfig` model.

### Step 7 — Configure in config.json

```json
{
  "channels": {
    "instagram": {
      "enabled": true,
      "app_secret": "your_meta_app_secret",
      "verify_token": "a_random_string_you_choose",
      "page_access_token": "your_page_access_token",
      "ig_user_id": "your_ig_scoped_user_id",
      "slack_bot_token": "xoxb-your-slack-bot-token",
      "slack_draft_channel": "C0XXXXXXXXX",
      "slack_signing_secret": "your_slack_signing_secret",
      "webhook_port": 5005
    }
  }
}
```

### Step 8 — Meta App setup checklist

Do these in the Meta Developer Console before testing:

1. Create a Meta App → Business type
2. Add the **Messenger** product (covers Instagram messaging)
3. Under Webhooks, subscribe to `messages` for your Instagram account
4. Set Callback URL: `https://your-server.com/webhook/instagram`
5. Set Verify Token to match `verify_token` in your config
6. Request permissions: `instagram_manage_messages`, `pages_messaging`
7. Complete Business Verification and App Review (required for production; use Development mode with whitelisted test accounts meanwhile)

### Step 9 — Add to AGENTS.md

In your nanobot workspace `~/.nanobot/workspace/AGENTS.md`, add:

```markdown
## Instagram DMs
When you receive a message from the instagram channel:
1. Read the customer's message carefully.
2. Consult the knowledge base files in this workspace for product/policy info.
3. Draft a helpful, on-brand reply.
4. Your reply will be posted to Slack where a human will review it and choose to send,
   edit and send, or discard it.
5. Do NOT attempt to send the reply yourself — there is no Instagram send tool.
```

### Verification

```python
# tests/test_instagram_channel.py
from nanobot.channels.instagram import InstagramChannel
import pytest, json

def test_agent_send_is_unconditionally_disabled():
    ch = InstagramChannel.__new__(InstagramChannel)
    with pytest.raises(NotImplementedError):
        ch.send_message("some_user", "some text")

def test_meta_signature_rejects_bad_sig(client):
    # POST to /webhook/instagram with wrong X-Hub-Signature-256
    # Assert 401

def test_slack_signature_rejects_bad_sig(client):
    # POST to /slack/actions with wrong X-Slack-Signature
    # Assert 401

def test_post_draft_builds_correct_blocks(monkeypatch):
    # Monkeypatch requests.post
    # Call post_draft_to_slack(...)
    # Assert ACTION_SEND, ACTION_EDIT_SEND, ACTION_DISCARD all appear in blocks

def test_send_action_calls_instagram_api(monkeypatch):
    # Monkeypatch _send_instagram_message to capture calls
    # Simulate _handle_slack_action with ACTION_SEND payload
    # Assert _send_instagram_message was called with correct sender_id and draft text

def test_discard_action_does_not_call_instagram_api(monkeypatch):
    # Monkeypatch _send_instagram_message — assert it is NEVER called
    # Simulate _handle_slack_action with ACTION_DISCARD payload
    # Assert _update_slack_message was called with "Discarded" status

def test_edit_modal_submit_sends_edited_text(monkeypatch):
    # Simulate view_submission payload with edited text
    # Assert _send_instagram_message called with the edited (not original draft) text
```

---

## Notes for the coding agent

- **Read before writing.** Study `nanobot/channels/email.py`, `nanobot/channels/slack.py`, and `nanobot/channels/base.py` before touching anything. The patterns matter.
- **Don't over-engineer.** Nanobot's value is its ~4,000-line simplicity. Keep additions minimal.
- **The agent send block is non-negotiable.** `InstagramChannel.send_message()` must raise unconditionally. `_send_instagram_message()` is the only real send path and is private — only reachable from human-triggered Slack action handlers.
- **Slack's 3-second rule.** The `/slack/actions` route must return 200 within 3 seconds or Slack will show an error. The actual Instagram API call happens in a background thread (`threading.Thread`). Don't do I/O in the route handler itself.
- **Double-click protection.** After any action (Send, Discard, or modal submit), `_update_slack_message()` replaces the action buttons with a status line. This prevents a second agent or human from acting on the same draft twice.
- **Test the OAuth flow manually first.** Run the Gmail auth helper once in a terminal before integrating with nanobot to confirm the token saves correctly.
- **Both webhooks share one port.** `/webhook/instagram` (Meta) and `/slack/actions` (Slack) are both registered on the same Flask app on port 5005. Only one process needs to run.
- **Instagram webhook requires HTTPS.** For local development, use `ngrok http 5005` and set the ngrok URL in both the Meta dashboard and the Slack App's Interactivity Request URL. For production, put nginx in front.
- **Meta App Review takes time.** Start Business Verification now — it can take days. Develop and test with whitelisted test accounts in Development mode in the meantime.
