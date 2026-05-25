# Prospr customer support — Gmail & Instagram integration

This fork wires **Gmail (IMAP + drafts)** and **Instagram DMs (Meta + Slack)** into nanobot. Use this doc together with the official platform docs; URLs and API shapes change over time.

---

## Python dependencies

Optional extras are defined in **`pyproject.toml`** at the repo root:

| Extra | Purpose |
|--------|--------|
| **`gmail`** | Google OAuth + Gmail API client libraries for `create_gmail_draft` |
| **`instagram`** | Flask + werkzeug (Meta **`/webhook/instagram/{accountKey}`** when `useWebhook` is `true`); Slack draft approvals use **Socket Mode** (no Slack HTTP route in nanobot) |
| **`dev`** | pytest, ruff, Flask for tests, etc. |

### Checked-out source (recommended for this fork)

From the **repository root** (the directory that contains `pyproject.toml`):

```bash
cd /path/to/nanobot
python3 -m venv .venv && . .venv/bin/activate
pip install -U pip wheel
pip install -e '.[gmail,instagram]'
```

Use only `'.[gmail]'` or `'.[instagram]'` if you do not need both channels yet.

Run nanobot, OAuth helpers, and pytest **in the same environment** so `import nanobot` resolves to this checkout.

### Released package from PyPI

If you install a published wheel instead of the repo:

```bash
pip install 'nanobot-ai[gmail]'
pip install 'nanobot-ai[instagram]'
```

The PyPI distribution name is **`nanobot-ai`** (see `name` in `pyproject.toml`).

---

## Starting without public Meta webhooks (polling only)

You can bring support online **without registering a public HTTPS callback for Meta** (no Instagram **messaging webhook** URL in the Meta app yet). Inbound mail and Instagram DMs are then discovered by **polling** on a fixed interval (up to once per minute).

### Gmail (email channel)

Inbound mail is **always pulled** over IMAP (nanobot connects to Gmail). There is **no** inbound HTTP webhook for email.

- **Polling-only (no IMAP IDLE):** set `imapIdleEnabled` to **`false`**. New mail is picked up on each **`pollIntervalSeconds`** cycle (clamped between **5** and **60** seconds).
- **Default with IDLE:** `imapIdleEnabled` **`true`** still does not expose a public URL; IDLE is an outbound connection to the IMAP server. Use polling-only if you prefer a simple timer or your provider handles IDLE poorly.

### Instagram (Meta → nanobot)

- Set **`useWebhook`** to **`false`**. Meta will not call your server for new DMs; nanobot uses the **Graph API** (`GET /{page-id}/conversations?platform=INSTAGRAM`, …) on **`pollIntervalSeconds`** instead.
- Each **`accounts[]`** entry still needs **`pageId`**, **`pageAccessToken`**, and channel-level **`pollIntervalSeconds`** set to a positive value (default **60**).
- **`appSecret`** and **`verifyToken`** are **not** required in nanobot config until you turn webhooks on (see [Setup: Instagram](#setup-instagram-dm--slack-human-approved-send) §3).
- On the **Meta** side you still create a Developer app and obtain a Page token — you just **skip webhook URL registration** for now. See [Meta app — polling only](#3-meta-app--polling-only-usewebhook-false) in the setup section below.
- Later, when you have a public URL, set **`useWebhook`** to **`true`**, add per-account **`appSecret`** / **`verifyToken`**, configure Meta’s webhook for that account, and optionally keep **`pollFallbackEnabled`** **`true`** for redundancy.

### Slack (human Send / Edit / Discard)

Instagram draft approvals use **Slack Socket Mode** only: button clicks and modal submissions arrive over the app’s WebSocket connection. **No** public **Request URL** / **`/slack/actions`** endpoint is required for Instagram. Draft messages are still posted **outbound** via `chat.postMessage` using the bot token.

**Example — polling-first `channels.email` snippet**

```json
"email": {
  "enabled": true,
  "consentGranted": true,
  "imapHost": "imap.gmail.com",
  "imapPort": 993,
  "imapUsername": "support@yourcompany.com",
  "imapPassword": "your-app-password",
  "imapUseSsl": true,
  "imapIdleEnabled": false,
  "pollIntervalSeconds": 60,
  "allowFrom": ["*"]
}
```

**Example — polling-first `channels.instagram` snippet**

```json
"instagram": {
  "enabled": true,
  "consentGranted": true,
  "useWebhook": false,
  "pollIntervalSeconds": 60,
  "slackBotToken": "xoxb-...",
  "slackDraftChannel": "C0XXXXXXXXX",
  "slackAppToken": "xapp-...",
  "allowFrom": ["*"],
  "accounts": [
    {
      "accountKey": "brand_main",
      "label": "Brand Main",
      "pageId": "YOUR_FACEBOOK_PAGE_ID",
      "pageAccessToken": "YOUR_PAGE_ACCESS_TOKEN"
    }
  ]
}
```

---

## Setup: Gmail (mailbot path)

You need **two parallel tracks**: (1) **IMAP** for inbound support mail into nanobot, and (2) **Gmail API + OAuth** so the agent can call `create_gmail_draft` (drafts only — no SMTP).

### 1. Python packages

Install the **`[gmail]`** extra ([Python dependencies](#python-dependencies) — use **checked-out source** with `pip install -e '.[gmail]'` from the repo root).

### 2. Google Cloud — Gmail API & OAuth (drafts)

Follow the official flow (adapted for our config keys and scope):

1. Create or select a [Google Cloud project](https://developers.google.com/workspace/guides/create-project).
2. **Enable the Gmail API**: [Enable Gmail API](https://console.cloud.google.com/flows/enableapi?apiid=gmail.googleapis.com).
3. **OAuth consent screen** ([Branding / Audience / scopes](https://developers.google.com/workspace/guides/configure-oauth-consent)):
   - Configure app name, support email, etc.
   - Add **Data access** scopes: `gmail.compose` and `gmail.readonly` (see [Gmail API scopes](https://developers.google.com/workspace/gmail/api/auth/scopes)).
   - *External* user type is required if the mailbox owner is outside your Workspace org; you may need verification for wide production use. *Internal* works for Workspace-only testing.
4. **Create OAuth client**: [Clients](https://console.developers.google.com/auth/clients) → type **Desktop app** (same pattern as the [Python quickstart](https://developers.google.com/workspace/gmail/api/quickstart/python)).
5. Note the **client ID** and **client secret** from the downloaded JSON (`installed.client_id`, `installed.client_secret`).

### 3. One-time refresh token (browser)

From the repo root (with `pip install -e '.[gmail]'`):

```bash
python3 scripts/gmail_draft_oauth_setup.py
```

The script prompts for your Desktop OAuth **client ID** and **client secret** (not a `credentials.json` file), opens a browser to sign in as the support mailbox, and prints `GMAIL_REFRESH_TOKEN` plus a sample `tools.gmailDraft` config block. Copy the refresh token into your secret store.

Alternatively, use any flow that yields a refresh token (e.g. [Python quickstart](https://developers.google.com/workspace/gmail/api/quickstart/python)).

Nanobot does **not** write OAuth tokens to disk. Set environment variables (or inject into config):

- `GMAIL_CLIENT_ID`
- `GMAIL_CLIENT_SECRET`
- `GMAIL_REFRESH_TOKEN`

Add to `~/.nanobot/config.json`:

```json
{
  "tools": {
    "gmailDraft": {
      "clientId": "${GMAIL_CLIENT_ID}",
      "clientSecret": "${GMAIL_CLIENT_SECRET}",
      "refreshToken": "${GMAIL_REFRESH_TOKEN}"
    }
  }
}
```

**Migration:** If you previously used `~/.nanobot/gmail_token.json`, read the `refresh_token` field from that file once, move it to `${GMAIL_REFRESH_TOKEN}`, then delete `gmail_token.json` and `gmail_credentials.json`.

### 4. Gmail IMAP — inbound email channel

1. In the Google account that receives support mail, turn on [IMAP](https://support.google.com/mail/answer/7126229).
2. If the account uses **2-Step Verification**, create an [App Password](https://support.google.com/accounts/answer/185833) and use it as `imapPassword` — not your normal login password.
3. **DKIM/SPF:** Gmail→Gmail often includes `Authentication-Results`. If you poll mail that lacks those headers, you may need `verifyDkim` / `verifySpf` `false` in config (weaker anti-spoofing).

### 5. `~/.nanobot/config.json` — `channels.email` + `tools.gmailDraft`

SMTP is **not** used for outbound (`create_gmail_draft` only). Omit `smtpHost` or leave blank. Combine with `tools.gmailDraft` from step 3.

```json
{
  "channels": {
    "email": {
      "enabled": true,
      "consentGranted": true,
      "imapHost": "imap.gmail.com",
      "imapPort": 993,
      "imapUsername": "support@yourcompany.com",
      "imapPassword": "your-app-password-or-app-specific-password",
      "imapUseSsl": true,
      "imapIdleEnabled": true,
      "pollIntervalSeconds": 60,
      "autoReplyEnabled": true,
      "allowFrom": ["*"]
    }
  },
  "tools": {
    "gmailDraft": {
      "clientId": "${GMAIL_CLIENT_ID}",
      "clientSecret": "${GMAIL_CLIENT_SECRET}",
      "refreshToken": "${GMAIL_REFRESH_TOKEN}"
    }
  }
}
```

Restart nanobot with the gateway so the email channel starts. Inbound messages appear in the agent; replies go out only via **`create_gmail_draft`** in Gmail, not SMTP. For **polling-only** inbound (no IMAP IDLE), see [Starting without public Meta webhooks](#starting-without-public-meta-webhooks-polling-only) — same section covers Gmail IMAP polling.

**References:** [Gmail API drafts.create](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.drafts/create), [Troubleshoot auth](https://developers.google.com/workspace/gmail/api/troubleshoot-authentication-authorization).

---

## Setup: Instagram DM + Slack (human-approved send)

This channel listens for **Instagram direct messages to your business** (Messenger-style webhooks + optional Graph poll), runs the agent, posts drafts to Slack, and **only sends to Instagram when a human clicks** Send / Edit & Send in Slack.

### 1. Python packages

Install the **`[instagram]`** extra ([Python dependencies](#python-dependencies) — from the repo root: `pip install -e '.[instagram]'` or combine with Gmail: `pip install -e '.[gmail,instagram]'`).

### 2. Prerequisites (Meta)

- **Instagram Professional** (Business or Creator) linked to a **Facebook Page**.
- **Meta Developer** app ([developers.facebook.com](https://developers.facebook.com/)) per Instagram account (internal-use apps are fine — see [multi-account runbook](instagram_multi_account_meta_setup.md)).
- **Public HTTPS URL** for **Meta** webhooks only when `useWebhook` is `true` (for local dev, use **ngrok** or similar in front of `webhookPort`). If you start with **[polling only](#starting-without-public-meta-webhooks-polling-only)** (`useWebhook: false`), you do **not** register a Meta callback URL; **Slack** approvals still work over **Socket Mode** (outbound connection from nanobot — no public Slack URL).

### 3. Meta app — polling only (`useWebhook: false`)

Use this path when you cannot expose a public HTTPS endpoint yet. Nanobot pulls new DMs via Graph on a timer; human-approved replies still go out with **`POST /me/messages`** using the same Page token.

**Configure on Meta (repeat per Instagram account):**

1. **Instagram + Page**
   - Confirm the account is **Professional** (Business or Creator) and linked to the correct **Facebook Page**.
   - Your Meta Developer login must have at least **Moderate** task access on that Page ([Page tasks](https://developers.facebook.com/docs/pages-api/overview#tasks)).

2. **Create a Meta app** ([developers.facebook.com/apps](https://developers.facebook.com/apps/))
   - One app **per** Instagram account (recommended for multi-brand routing).
   - Add the products Meta’s current [Instagram Messaging get started](https://developers.facebook.com/docs/messenger-platform/instagram/get-started/) guide requires (typically **Messenger** / Instagram messaging on the app).
   - For **your own** business assets, follow [Apps for your own business](https://developers.facebook.com/docs/messenger-platform/instagram/app-review/apps-for-your-own-business) — you usually do **not** need full App Review before testing on Pages you control.

3. **Grant messaging permissions and get a Page access token**
   - Via [Graph API Explorer](https://developers.facebook.com/tools/explorer/) or Facebook Login: request scopes Meta lists for Instagram messaging — at minimum **`instagram_manage_messages`**, plus **`instagram_basic`** and **`pages_manage_metadata`** (names can change; use Meta’s get-started doc as source of truth).
   - Call **`GET /me/accounts`** with the User token → note the **`id`** of the Page linked to Instagram → **`pageId`** in nanobot config.
   - Exchange for a **long-lived Page access token** ([long-lived Page token guide](https://developers.facebook.com/docs/facebook-login/guides/access-tokens/get-long-lived#get-a-long-lived-page-access-token)) → **`pageAccessToken`** in nanobot config.
   - Optional shortcut: **App Dashboard → Messenger → Instagram Settings** can generate Page tokens when Meta shows that tool for your app.

4. **Connect the Page to your app**
   - In the app dashboard, under **Messenger → Instagram** (or **Add products → Instagram**), add / connect the Facebook Page tied to the Instagram account so the app can call messaging APIs for that Page.

5. **Enable Instagram “Connected tools” (required for API access)**
   - On the Instagram account: **Settings → Messages and story replies → Message controls → Connected tools → Allow access to messages** ([Meta get started §4](https://developers.facebook.com/docs/messenger-platform/instagram/get-started/)).
   - Without this toggle, Graph poll and send calls may succeed for token setup but return empty or fail on live DMs.

6. **Validate before starting nanobot**

   ```http
   GET https://graph.facebook.com/v19.0/{page-id}/conversations?platform=INSTAGRAM&access_token={pageAccessToken}
   ```

   Expect **HTTP 200** and a `data` array (empty is OK if no DMs yet). A permission error here means fix token scopes or Page/app linkage before relying on poll mode.

7. **Optional: `igUserId`**
   - If you know the Instagram professional account’s Graph user id, set **`igUserId`** on the account entry so poll mode can skip messages “from” your own account when Meta returns them in the thread list.

**Do not configure yet (polling only):**

| Meta dashboard item | Polling-only? |
|---------------------|---------------|
| Webhooks → Callback URL | **Skip** |
| Webhooks → Verify token | **Skip** (no nanobot `verifyToken` until webhooks) |
| App secret in nanobot config | **Skip** (only needed for webhook HMAC when `useWebhook: true`) |
| Public HTTPS / `webhookPort` | **Skip** |
| Subscribe webhook fields (`messages`, …) | **Skip** |

You **do** still need the Meta app, Page connection, long-lived **`pageAccessToken`**, and **`pageId`** — polling and Slack-approved send both use Graph with that token.

### 4. Meta app — webhooks (`useWebhook: true`)

When you have a public URL, add webhook setup **on top of** the polling prerequisites above:

1. **App Dashboard** → note **App secret** → that account’s **`appSecret`** in `accounts[]`.
2. **Webhooks** ([Instagram / Messenger webhook docs](https://developers.facebook.com/docs/messenger-platform/instagram/features/webhook/)):
   - Callback URL: `https://YOUR_PUBLIC_HOST/webhook/instagram/{accountKey}` (must match the account’s `accountKey` in config).
   - **Verify token**: any long random string you choose → that account’s **`verifyToken`** (must match exactly).
   - Subscribe to **messages** (and any other fields Meta lists for Instagram messaging).
   - Subscribe the **Page** to this app’s webhook (same Page as `pageId`).
3. Keep **`pageId`** + **`pageAccessToken`** — still required if **`pollFallbackEnabled`** is `true` (default), or for thread history on Slack review cards.

Use [Graph API Explorer](https://developers.facebook.com/tools/explorer/) to confirm `/{page-id}/conversations?platform=INSTAGRAM` works with your token.

### 5. Slack app (draft review & Socket Mode)

1. Create a Slack app → **OAuth scopes** for the bot (minimum): `chat:write`, `chat:update`, `views.open` (for Edit & Send modal).
2. Install to workspace; copy **Bot User OAuth Token** → `slackBotToken` (`xoxb-...`).
3. Create or pick a channel for drafts; copy its **channel ID** (starts with `C`) → `slackDraftChannel`.
4. **Socket Mode** → enable it. **Basic Information** → **App-Level Tokens** → **Generate token** with scope **`connections:write`** → `slackAppToken` (`xapp-...`).
5. You do **not** need **Interactivity** “Request URL” for Instagram (no `/slack/actions` in nanobot). Interactivity still works when delivered over Socket Mode.

### 6. Networking / ports

Default bind: **`webhookHost`** `0.0.0.0`, **`webhookPort`** `5005`. When **`useWebhook`** is **`true`**, put TLS termination (or ngrok) in front so **Meta** can reach `https://.../webhook/instagram/{accountKey}`. When **`useWebhook`** is **`false`**, nanobot does **not** start the Meta webhook HTTP server — no inbound port needs to be exposed for Instagram. Slack does not call this URL for Instagram button actions (Socket Mode).

### 7. `~/.nanobot/config.json` — `channels.instagram`

**Webhook mode** (after Meta callback is registered — [§4](#4-meta-app--webhooks-usewebhook-true)):

```json
{
  "channels": {
    "instagram": {
      "enabled": true,
      "consentGranted": true,
      "useWebhook": true,
      "pollFallbackEnabled": true,
      "pollIntervalSeconds": 60,
      "slackBotToken": "xoxb-...",
      "slackDraftChannel": "C0XXXXXXXXX",
      "slackAppToken": "xapp-...",
      "webhookHost": "0.0.0.0",
      "webhookPort": 5005,
      "allowFrom": ["*"],
      "accounts": [
        {
          "accountKey": "brand_main",
          "label": "Brand Main",
          "pageId": "your-facebook-page-id",
          "pageAccessToken": "your-page-access-token",
          "igUserId": "",
          "appSecret": "your-meta-app-secret",
          "verifyToken": "your-random-verify-string"
        }
      ]
    }
  }
}
```

**Polling-only mode** (no Meta webhook — [§3](#3-meta-app--polling-only-usewebhook-false)):

```json
{
  "channels": {
    "instagram": {
      "enabled": true,
      "consentGranted": true,
      "useWebhook": false,
      "pollIntervalSeconds": 60,
      "slackBotToken": "xoxb-...",
      "slackDraftChannel": "C0XXXXXXXXX",
      "slackAppToken": "xapp-...",
      "allowFrom": ["*"],
      "accounts": [
        {
          "accountKey": "brand_main",
          "label": "Brand Main",
          "pageId": "your-facebook-page-id",
          "pageAccessToken": "your-long-lived-page-access-token",
          "igUserId": ""
        }
      ]
    }
  }
}
```

- **`useWebhook`:** `true` = Meta pushes DMs immediately. `false` = poll-only (needs per-account `pageId` + `pageAccessToken` only — no `appSecret` / `verifyToken`); use if you cannot expose webhooks yet.
- **`pollFallbackEnabled`:** when `true` with webhooks, still polls the Conversations API on an interval (≤60s) to catch missed deliveries.
- **`igUserId`:** optional; when set with **poll** mode, messages “from” that ID can be skipped to avoid treating your bot as the customer (if Meta returns your IGSID there).

### 8. Multiple Instagram accounts (internal app per account)

Use one **`accounts`** array entry per Instagram account. Each account should have its **own internal-use Meta app** with its own **`pageAccessToken`** and **`pageId`** (add **`appSecret`** / **`verifyToken`** when you enable webhooks). Nanobot routes inbound DMs and approved sends by `accountKey`.

**Poll-first (recommended to start):** set `useWebhook: false`. Only `pageId` + `pageAccessToken` are required per account in nanobot config (Meta app + Page token setup still required — see [§3](#3-meta-app--polling-only-usewebhook-false)).

**Webhooks later:** register each Meta app to  
`https://YOUR_PUBLIC_HOST/webhook/instagram/{accountKey}`  
(with matching per-account `verifyToken` / `appSecret` in config — see [§4](#4-meta-app--webhooks-usewebhook-true)).

Full Meta setup steps: [`docs/instagram_multi_account_meta_setup.md`](instagram_multi_account_meta_setup.md).

```json
{
  "channels": {
    "instagram": {
      "enabled": true,
      "consentGranted": true,
      "useWebhook": false,
      "pollIntervalSeconds": 60,
      "slackBotToken": "xoxb-...",
      "slackDraftChannel": "C0XXXXXXXXX",
      "slackAppToken": "xapp-...",
      "allowFrom": ["*"],
      "accounts": [
        {
          "accountKey": "brand_main",
          "label": "Brand Main",
          "pageId": "111111111111111",
          "pageAccessToken": "EAAB...",
          "igUserId": ""
        },
        {
          "accountKey": "brand_outlet",
          "label": "Brand Outlet",
          "pageId": "222222222222222",
          "pageAccessToken": "EAAB...",
          "igUserId": ""
        }
      ]
    }
  }
}
```

**References:** [Instagram Messaging get started](https://developers.facebook.com/docs/messenger-platform/instagram/get-started/), [Webhook verification](https://developers.facebook.com/docs/messenger-platform/webhooks/), [Send API](https://developers.facebook.com/docs/messenger-platform/instagram/features/send-message/), [Page conversations](https://developers.facebook.com/docs/graph-api/reference/page/conversations/), [Slack Socket Mode](https://api.slack.com/apis/connections/socket).

---

## Gmail — technical summary

### Inbound (email channel)

- **Mechanism:** IMAP to Gmail (`imap.gmail.com:993`). Optional **IMAP IDLE** (`imapIdleEnabled`, default `true`) for near-real-time delivery; otherwise polling at `pollIntervalSeconds` (clamped **5–60** seconds).
- **Google / IMAP:** [Gmail IMAP](https://support.google.com/mail/answer/7126229) — use an [App Password](https://support.google.com/accounts/answer/185833) if the account uses 2-Step Verification.
- **RFC 2177 IDLE:** Supported by Gmail; nanobot opens a short-lived IDLE session, waits for `EXISTS`/`RECENT`/`EXPUNGE` or a timeout, then issues `DONE`, logs out, and fetches `UNSEEN` messages.

### Outbound (drafts only)

- **Mechanism:** Agent tool `create_gmail_draft` → Gmail API `users.drafts.create` — **never** SMTP and never `users.messages.send`.
- **Credentials:** `tools.gmailDraft` in config (`clientId`, `clientSecret`, `refreshToken`); access tokens in memory only.

### Optional Python packages

Install **`[gmail]`** as in [Python dependencies](#python-dependencies) (`pip install -e '.[gmail]'` from source, or `pip install 'nanobot-ai[gmail]'` from PyPI).

---

## Instagram — technical summary

### Inbound — webhooks (immediate)

- **Mechanism:** Meta **POST** to your HTTPS URL with JSON body. **`X-Hub-Signature-256`**: `sha256=` + HMAC-SHA256 of **raw POST body** using the app secret ([Instagram Messaging webhooks](https://developers.facebook.com/docs/messenger-platform/instagram/features/webhook/)).
- **Verification GET:** Echo **`hub.challenge`** as **200** plain text after validating **`hub.verify_token`**.

### Inbound — poll (primary when `useWebhook: false`, or fallback when `pollFallbackEnabled: true`)

- **Mechanism:** `GET .../{page-id}/conversations?platform=INSTAGRAM&...` ([Page conversations](https://developers.facebook.com/docs/graph-api/reference/page/conversations/)).
- **Meta prerequisites:** long-lived Page access token with `instagram_manage_messages` (and related scopes), Page linked to app, Instagram **Connected tools → Allow access to messages** enabled. No webhook URL on Meta.

### Outbound — send (human only, Slack)

- **`POST .../me/messages`** with Page access token — [Send API](https://developers.facebook.com/docs/messenger-platform/instagram/features/send-message/).

### Slack

- **Socket Mode** — `slackAppToken` (`xapp-...`) + `slackBotToken`; interactive payloads (block actions, view submissions) are ACKed on the socket then handled internally ([Socket Mode](https://api.slack.com/apis/connections/socket)).

### Optional Python packages

Install **`[instagram]`** as in [Python dependencies](#python-dependencies) (`pip install -e '.[instagram]'` from source, or `pip install 'nanobot-ai[instagram]'` from PyPI).

---

## Prompt templates (agent)

### Email

- Use `create_gmail_draft` to draft replies to support emails (human review in Gmail).
- NEVER attempt to send email directly. There is no send tool; the email channel does not send via SMTP.

### Instagram DMs

When you receive a message from the instagram channel:

1. Read the customer's message carefully.
2. Consult the knowledge base files in this workspace for product and policy information.
3. If a reply is warranted, call `create_instagram_draft` with the proposed reply text (and optional reviewer notes). This queues the draft for Slack human review — it does **not** send to Instagram.
4. If no reply is needed, do **not** call `create_instagram_draft`. A Slack review card will still be posted indicating no reply was suggested; humans can use **Edit & Send** if they disagree.
5. Do NOT attempt to send the reply yourself — there is no Instagram send tool for the agent.
6. Each Instagram customer conversation appears as one Slack thread; review cards include the customer message for context.
