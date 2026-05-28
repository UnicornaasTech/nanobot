# Prospr custom implementations

Reference for **fork-specific** behavior on top of upstream nanobot (`HKUDS/nanobot`). Tracks **code changes** and **config keys** (including upstream keys that gain new behavior in this fork).

Operational setup (Google Cloud, Meta dashboards, ngrok, etc.) stays in vendor docs.

**Private repo:** `prospr-app/nanobot-prospr` — fork-only commits on top of upstream `HKUDS/nanobot` `main`.

**Upstream baseline:** merged `public/main` @ `8c0b2c1a` (2026-05-22); prior common ancestor `26665823`.

| Commit     | Summary                                                                                          |
| ---------- | ------------------------------------------------------------------------------------------------ |
| `881cba4b` | Gmail + Instagram channels/tools; Slack **persist-without-reply** (`no_reply`); devcontainer     |
| `32bb1862` | Log line for read-only (`no_reply`) persists                                                     |
| `42ee6ea1` | Multi-account Instagram, `create_instagram_draft`, unified-session delivery guard, deploy script |
| (later)    | Eager knowledge, Dream/edit_file/provider-retry tweaks — see git log on `main`                   |

---

## Modifications

### Slack: persist channel traffic without replying (`no_reply`)

When `channels.slack.groupPolicy` is **`mention`** (default), messages in channels/groups that do **not** @mention the bot used to be **dropped**. The fork **ingests** them for session history but **does not** run the LLM or send outbound.

| Piece                                       | Behavior                                                                                                                                                                                                       |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`SlackChannel`**                          | Sets `no_reply=True` when `channel_type != "im"` and `_should_respond_in_channel()` is false. Still downloads files, builds thread context, and publishes inbound. Skips `:eyes:` reaction when `no_reply`.    |
| **`InboundMessage.no_reply`**               | New bus field (`nanobot/bus/events.py`).                                                                                                                                                                       |
| **`BaseChannel._handle_message`**           | Passes `no_reply`; disables `_wants_stream` when `no_reply` so no streaming outbound path is armed.                                                                                                            |
| **`AgentLoop._persist_no_reply_user_turn`** | Appends a **user** message to the session **without** `pending_user_turn` metadata (not treated as an unanswered prompt). Logs `Reading-only message from {channel}:{sender}: …`.                              |
| **`AgentLoop._dispatch`**                   | If `no_reply` and content is not a dispatchable slash command → persist and **return** (no LLM, no outbound).                                                                                                  |
| **Mid-turn / unified session**              | If a session already has an active turn and a `no_reply` follow-up arrives, `_append_no_reply_when_session_unlocked` runs in the background **after** the session lock is free (no race with in-flight turns). |
| **Slash commands**                          | `no_reply` does **not** block dispatchable commands (e.g. `/help` still runs).                                                                                                                                 |

**Trigger:** `channels.slack.groupPolicy: "mention"` + message in a channel/group without `@bot` mention. DMs (`im`) always get full replies.

### Slack: ignore Instagram draft-review button clicks

When `channels.instagram` and `channels.slack` share the **same** Slack app (`botToken` / `appToken` duplicated as `slackBotToken` / `slackAppToken`), Slack delivers interactive payloads to **both** Socket Mode clients. **`SlackChannel._on_block_action`** ignores `block_actions` whose `action_id` starts with **`ig_`** (Instagram Send / Edit & Send / Discard) so they are not forwarded to the agent. Review cards posted by the bot are already ignored as `subtype: bot_message`. Normal Slack UI buttons (`btn_*`) are unchanged.

**Typical setup:** `slackDraftChannel` is the same support channel as other traffic, with `channels.slack.groupPolicy: "open"` — human messages still get full agent replies; Instagram approval clicks do not.

**Config example** (`~/.nanobot/config.json` fragment — merge with your existing file):

```json
{
  "channels": {
    "slack": {
      "enabled": true,
      "botToken": "xoxb-...",
      "appToken": "xapp-...",
      "groupPolicy": "mention"
    }
  }
}
```

With `"groupPolicy": "open"`, every channel message gets a full agent turn (upstream behavior; fork `no_reply` path is not used). DMs always reply regardless of `groupPolicy`.

**Tests:** `tests/agent/test_loop_no_reply.py`

### Eager knowledge (non-unified cross-channel recall)

When `agents.defaults.eagerKnowledge.enabled` is **true**, session traffic is promoted into `memory/history.jsonl` soon after persist — without waiting for token-overflow consolidation. Works with **`unifiedSession: false`** so each Slack channel/DM/thread keeps its own session file while **Recent History** and Dream still see channel ambient traffic.

| Piece                                                            | Behavior                                                                                                                                                                                                                                                                                                                                                       |
| ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`EagerKnowledgeManager`** (`nanobot/agent/eager_knowledge.py`) | Cursored flush (`_prospr_eager_cursor`). Batch ≥ `minBatch` → `Consolidator.archive()`. Smaller batches flush after `singletonIdleS` via raw `[EAGER singleton …]` append (no LLM). Token overflow / file-cap consolidation skip indices already covered by the eager cursor (no duplicate `history.jsonl` entries).                                           |
| **`Consolidator.archive()`** (shared)                            | Skips empty payloads and no-op LLM outputs (`(nothing)`, `[no summary]`). Inlines session `media` (images to vision blocks, documents via text extraction) with per-file and prompt budget caps. System prompt includes labeled **REFERENCE ONLY** bootstrap (`AGENTS.md`, `SOUL.md`, `USER.md`, `TOOLS.md`) so summaries do not repeat standing instructions. |
| **Triggers**                                                     | After `no_reply` persist and after normal turn `_state_save`; idle tick in `AgentLoop.run()` for cold singletons.                                                                                                                                                                                                                                              |
| **Slack provenance**                                             | `slack_ts`, `slack_thread_ts`, `slack_root_ts`, `slack_reply_kind` on stored user rows; archived lines prefixed e.g. `[slack C123 reply root=…]`.                                                                                                                                                                                                              |

**Config** (`agents.defaults.eagerKnowledge`):

| Key              | Default | Meaning                                           |
| ---------------- | ------- | ------------------------------------------------- |
| `enabled`        | `false` | Turn on eager promotion                           |
| `minBatch`       | `3`     | LLM archive when pending chunk reaches this size  |
| `singletonIdleS` | `120`   | Raw flush for smaller chunks after this idle time |
| `maxBatch`       | `20`    | Max messages per eager flush                      |

**Config example** (works best with `unifiedSession: false` so each Slack surface keeps its own session file):

```json
{
  "agents": {
    "defaults": {
      "unifiedSession": false,
      "eagerKnowledge": {
        "enabled": true,
        "minBatch": 3,
        "singletonIdleS": 120,
        "maxBatch": 20
      }
    }
  }
}
```

**Tests:** `tests/agent/test_eager_knowledge.py`, `tests/agent/test_loop_no_reply.py`

### Generic memory prompts (`genericMemoryOnly`)

Customer-support deployments can store **generalized phenomena only** (playbooks, recurring issues, product patterns) without contradicting default memory behavior in `SOUL.md` / `USER.md`.

When `agents.defaults.genericMemoryOnly` is **true**, Consolidator and Dream use alternate bundled templates (`*_generic.md`) instead of the upstream `consolidator_archive.md` / `dream_phase1.md` / `dream_phase2.md`. Template selection: [`nanobot/agent/memory_prompts.py`](nanobot/agent/memory_prompts.py).

| Piece                        | Behavior                                                                                                                                              |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`Consolidator.archive()`** | Summarizes only cross-case patterns; forbids customer PII in `history.jsonl` bullets.                                                                 |
| **Archive LLM failure**      | Appends a short withheld marker — **no** `[RAW]` transcript dump.                                                                                     |
| **`Dream`**                  | Phase 1/2 use generic prompts: `USER.md` = operator/team only; `MEMORY.md` = generalized playbooks.                                                   |
| **Mutual exclusion**         | Config load **fails** if `genericMemoryOnly` and `eagerKnowledge.enabled` are both true (eager singleton raw flushes would bypass de-identification). |

**Config** (`agents.defaults.genericMemoryOnly`):

| Key                 | Type | Default | Meaning                                                              |
| ------------------- | ---- | ------- | -------------------------------------------------------------------- |
| `genericMemoryOnly` | bool | `false` | Use de-identified memory-gathering prompts for Consolidator + Dream. |

**Config example** (customer support; eager knowledge off):

```json
{
  "agents": {
    "defaults": {
      "genericMemoryOnly": true,
      "eagerKnowledge": { "enabled": false }
    }
  }
}
```

See also upstream memory overview: [`docs/memory.md`](memory.md).

**Tests:** `tests/config/test_generic_memory_config.py`, `tests/agent/test_consolidator.py`, `tests/agent/test_dream.py`

### Agent loop tweaks (local)

- **Dream** (`memory.py`, `dream_phase*.md`, optional `*_generic.md`): Defer batches stuck on repeated stale `edit_file`; prompts nudge read-after-edit and fewer auto-skills.
- **`edit_file`** (`filesystem.py`): Stale-read warning included in `old_text` not-found errors when applicable.
- **Provider retry** (`base.py`): Also retry on truncated/non-JSON bodies (`expecting value`, `jsondecodeerror`).
- **Empty-response fallback** (`fallback_provider.py`, `runner.py`): When the primary model returns a blank successful reply (after the usual two silent retries on the same model), configured `agents.defaults.fallbackModels` are tried once each before the no-tools finalization prompt — same presets as error failover, skipped when answer text was already streamed. If finalization is still blank, fallbacks are tried once more.
- **MCP endpoint loop protection** (`nanobot/utils/runtime.py`, `nanobot/agent/runner.py`): Per-turn throttle for repeated identical failing `mcp_*` tool calls (same tool name, normalized arguments, and error signature; third attempt blocked). Non-retryable MCP `400`/`404` responses with `validation_error` or `object_not_found` return an explicit “stop retrying this endpoint” payload instead of the generic “try a different approach” hint — reduces runaway Notion-style retry loops and downstream LLM 300s timeouts.

**Tests:** `tests/utils/test_mcp_endpoint_throttle.py`, `tests/agent/test_runner_tool_execution.py`, `tests/agent/test_runner_safety.py`

### Unified session: delivery-target guard (`unified_delivery.py`)

Extends upstream **`agents.defaults.unifiedSession`** (`unified:default` session shared across channels).

| Piece                       | Behavior                                                                                                                                                                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`DeliveryTarget`**        | `(channel, chat_id, slack_thread_ts?)` — outbound routing identity.                                                                                                                                                                                    |
| **Mid-turn injection**      | While a turn is active, follow-ups normally go to `_pending_queues`. With unified session on, injection only happens if the new message’s delivery target **matches** the active turn’s origin (same channel, chat, and Slack thread when applicable). |
| **Cross-surface follow-up** | Mismatched follow-ups are **not** queued on the active turn; they are **`_dispatch`’d as a separate turn** (after the session lock frees), so replies go to the correct channel/thread.                                                                |
| **`no_reply` + unified**    | Cross-surface `no_reply` messages use background persist when mid-turn injection is blocked.                                                                                                                                                           |

**Module:** `nanobot/agent/unified_delivery.py` (marked fork extension in docstring).

**Tests:** `tests/agent/test_unified_delivery.py`

### Optional Python extras (`pyproject.toml`)

| Extra       | Installs                                                                                  | Used by                                            |
| ----------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `gmail`     | `google-auth`, `google-auth-oauthlib`, `google-auth-httplib2`, `google-api-python-client` | `create_gmail_draft`, `gmail_auth`                 |
| `instagram` | `flask` (and werkzeug via Flask)                                                          | Meta webhook HTTP server when `useWebhook` is true |

`slack-sdk` is a **core** dependency (not the `instagram` extra). Instagram draft approvals use **Slack Socket Mode** only — there is **no** `/slack/actions` route and **no** `slackSigningSecret` config.

Install from repo root: `pip install -e '.[gmail,instagram]'`

### Email channel (`nanobot/channels/email.py`)

- **Inbound:** IMAP (`imapHost`, etc.). Optional **IMAP IDLE** when `imapIdleEnabled` is true (default); otherwise timer polling at `pollIntervalSeconds` (clamped **5–60** seconds).
- **Outbound disabled:** `send()` and `send_message()` always raise `NotImplementedError` directing the agent to `create_gmail_draft`. No SMTP `sendmail()` path runs even if SMTP fields are set.
- **Final reply reporting:** When `outboundSlackChannel` is set and `channels.slack` is enabled, the channel manager posts a short **heads-up** to that Slack target (header: `EMAIL DRAFT: From: … · Subject: … · Received at …`; no Message-ID), then a **thread reply** with truncated customer email body (`metadata.email_body`, max ~1 page) and the agent’s final reply inline. Progress/stream/retry traffic is not rerouted. Human replies in that thread follow normal Slack channel rules (`groupPolicy`, mentions). If `outboundSlackChannel` is missing, the final outbound is dropped with a warning (no email send attempt). Set `sendProgress: false` on email to suppress mid-turn outbound attempts entirely.
- **`message()` suppressed in email sessions:** [`MessageTool`](../nanobot/agent/tools/message.py) returns a `Message suppressed` notice for any `message()` call when the active session channel is `email`. This avoids duplicate heads-up posts. Errors and status notes should go in the final reply text — they appear in the threaded `Agent reply` section of the deterministic heads-up automatically.
- **`autoReplyEnabled`:** Present on `EmailConfig` (default `true`) but **not consulted** for delivery; outbound is blocked unconditionally in code.
- **`dropSubjectPatterns`:** List of glob patterns (`fnmatch`, case-insensitive) matched against the decoded inbound **Subject** immediately after self-sent filtering and **before** SPF/DKIM/`allowFrom` checks — so auto-replies and bounces that would fail auth still get dropped. When any pattern matches, the message is dropped before agent processing (no Slack heads-up, no session). The message is **not** marked `\\Seen` on IMAP (stays unread in the mailbox). In-process UID dedupe avoids re-delivering the same message on later polls in one gateway run; after a restart, the same UNSEEN message is fetched and dropped again. Brackets in patterns are **character classes** (same as shell globs), not literal text — use `*auto-reply*` rather than `*[Auto-Reply]*` unless you intend a class. Avoid a lone `*` pattern unless you intend to drop every message.

**Gmail IMAP credentials (`imapPassword`)** — separate from `tools.gmailDraft` OAuth:

| Use for `imapPassword`                                                 | Do **not** use                                          |
| ---------------------------------------------------------------------- | ------------------------------------------------------- |
| Google **App Password** (16 letters) for the mailbox in `imapUsername` | Normal Google sign-in password                          |
|                                                                        | `tools.gmailDraft` refresh token or OAuth client secret |

1. **2-Step Verification** must be **On** for the mailbox ([Google Account → Security](https://myaccount.google.com/security)). On **Google Workspace**, an admin may need to allow 2SV and app passwords for the user/OU.
2. **Create an app password:** [App passwords](https://myaccount.google.com/apppasswords) → app **Mail** (or custom name e.g. `nanobot-imap`) → copy the **16-character** password (shown as four groups of four; spaces are optional, hyphens are not part of the secret).
3. **Enable IMAP** in Gmail → Settings → **Forwarding and POP/IMAP** → [Enable IMAP](https://support.google.com/mail/answer/7126229). Workspace admins can restrict IMAP org-wide.
4. Set `imapPassword` to that value, or `"${GMAIL_PASSWORD}"` with `GMAIL_PASSWORD` set in the **same environment as the gateway process** (e.g. systemd `Environment=` / `EnvironmentFile=` — a shell export alone is not enough if the service does not inherit it). Config `${VAR}` refs are resolved at startup (`nanobot/config/loader.py`); missing vars fail fast with a clear error.

Startup log `IMAP IDLE unavailable ([AUTHENTICATIONFAILED] Invalid credentials)` means Gmail rejected `client.login(imapUsername, imapPassword)` — fix credentials/IMAP policy, not nanobot channel code. Confirm the running gateway uses the config file you edited (`nanobot gateway -c /path` or default `~/.nanobot/config.json` for the service user).

Full mailbox + OAuth draft setup: [`docs/prospr-customersupport-additions.md`](prospr-customersupport-additions.md#setup-gmail-mailbot-path).

**Config example** (SMTP fields are ignored for send; omit or leave blank):

```json
{
  "channels": {
    "email": {
      "enabled": true,
      "consentGranted": true,
      "imapHost": "imap.gmail.com",
      "imapPort": 993,
      "imapUsername": "support@yourcompany.com",
      "imapPassword": "${GMAIL_IMAP_APP_PASSWORD}",
      "imapUseSsl": true,
      "imapIdleEnabled": true,
      "pollIntervalSeconds": 60,
      "sendProgress": false,
      "outboundSlackChannel": "#customer-support-ai",
      "allowFrom": ["*"],
      "dropSubjectPatterns": ["*auto-reply*", "Out of office*"]
    },
    "slack": {
      "enabled": true,
      "botToken": "xoxb-...",
      "appToken": "xapp-..."
    }
  }
}
```

`outboundSlackChannel` accepts Slack channel names (`#general`), channel IDs (`C…`), or user handles (`@name` → DM). Polling-only inbound (no IMAP IDLE): set `"imapIdleEnabled": false` (same `pollIntervalSeconds` clamp, 5–60).

### Gmail draft tool (`nanobot/agent/tools/gmail_auth.py`, `gmail_draft.py`)

- Tool name: **`create_gmail_draft`**
- OAuth scopes: `gmail.compose` (drafts) + `gmail.readonly` (resolve reply thread / quote original). Re-run `scripts/gmail_draft_oauth_setup.py` after upgrading if lookup fails.
- **Config-only OAuth** under `tools.gmailDraft` (`clientId`, `clientSecret`, `refreshToken`). Values may use `${ENV_VAR}` interpolation. Access tokens are cached **in memory only** — no `gmail_token.json` or credential files on disk.
- Calls Gmail API `users.drafts.create` only — never `users.messages.send`.
- **Reply drafts:** on email sessions, `create_gmail_draft` auto-fills `in_reply_to` from inbound `message_id` (no LLM arg). The tool looks up the Gmail thread, sets `In-Reply-To` / `References`, matches subject (`Re:`), quotes the original below your reply body, and sets `threadId` so the draft appears on the conversation (not only in Drafts). Lookup/fallback failures are logged as warnings.
- **Tool result to agent:** short success text with Gmail URL only.
- Registered via tool auto-discovery (`nanobot/agent/tools/loader.py`). Enabled when `[gmail]` packages are importable **and** `tools.gmailDraft` is fully configured.

**Config example** (install `pip install -e '.[gmail]'`, enable email channel for inbound):

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

Obtain the refresh token once via `python3 scripts/gmail_draft_oauth_setup.py` (prompts for client ID/secret; no credential files on disk). See [`docs/prospr-customersupport-additions.md`](prospr-customersupport-additions.md) for full setup.

### Instagram channel (`nanobot/channels/instagram.py`)

New channel: Instagram DMs → agent → Slack review → human Send / Edit & Send / Discard → Meta send API.

> **REMARK / TODO (remove when sorted):** Poll mode (`_poll_conversations_for_account` in `nanobot/channels/instagram.py`) uses one heavy `GET /{pageId}/conversations?fields=messages.limit(10){…}` call. Meta often returns *“Please reduce the amount of data…”* or times out (30s). The light list (`?platform=INSTAGRAM` only) can return far fewer threads than the Instagram/Meta inbox UI — usually **Advanced Access** on `instagram_manage_messages`, not a pagination bug. **Fix:** refactor to Meta’s documented 3-step flow (list `id`/`updated_time` → `GET /{conversation-id}?fields=messages` → `GET /{message-id}`); persist seen message IDs / `updated_time` watermarks; prefer webhooks for inbound. There is **no** Graph `unread` filter — “new only” = webhooks or local dedupe, not `messages.limit` on the page list.

| Area                       | Behavior                                                                                                                                                                                                                                  |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Agent send**             | `send()` / `send_message()` raise `NotImplementedError`. Agent must use `create_instagram_draft`.                                                                                                                                         |
| **Turn completion**        | On agent turn end, `send()` posts a Slack review card (never calls Instagram).                                                                                                                                                            |
| **Draft tool**             | `create_instagram_draft` stores text in `instagram_review_state`; channel `consume_draft()` on turn end.                                                                                                                                  |
| **No reply suggested**     | If the agent does **not** call `create_instagram_draft`, a Slack card is still posted (“no reply suggested”); **Send** is hidden; **Edit & Send** remains so humans can reply manually.                                                   |
| **Slack approvals**        | Socket Mode (`slackAppToken` + `slackBotToken`). Interactive payloads ACK’d on the socket; send/discard run in background threads.                                                                                                        |
| **Shared Slack app**       | If the same `xoxb` / `xapp` is used for `channels.slack`, the Slack channel ignores `ig_*` block actions (see [Slack: ignore Instagram draft-review button clicks](#slack-ignore-instagram-draft-review-button-clicks)).                                                                                  |
| **Meta inbound — webhook** | When `useWebhook` is true: Flask on `webhookHost`:`webhookPort`. Per account: `GET`/`POST` `/webhook/instagram/{accountKey}` with per-account `verifyToken` / `appSecret` HMAC (`X-Hub-Signature-256`).                                   |
| **Meta inbound — poll**    | When `useWebhook` is false **or** `pollFallbackEnabled` is true: Graph `GET /v19.0/{pageId}/conversations?platform=INSTAGRAM` on each account on `pollIntervalSeconds` (clamped 5–60). Requires `pageId` + `pageAccessToken` per account. |
| **Meta outbound**          | `_send_instagram_message()` → `POST /v19.0/me/messages` with that account’s `pageAccessToken`. Only from Slack button/modal handlers.                                                                                                     |
| **Multi-account**          | `accounts[]` with distinct Meta apps recommended. `chatId` = `{accountKey}:{customerSenderId}` via `compose_chat_id()`. Slack cards show account label; send uses matching token.                                                         |
| **Inbound attachments**    | Webhook and poll paths parse `message.attachments`. Files with a CDN URL download to `~/.nanobot/data/media/instagram/`. Images/stickers go on `InboundMessage.media` for vision; PDF/DOCX/XLSX/PPTX and other `extract_documents`-supported types also go on `media` so the agent loop can inline extracted text. Video, audio, and other types are saved locally and described via markers (e.g. `[video: … — saved to …]`). Failed downloads get `[type: download failed]`. Image-only DMs (no `text`) are ingested. |
| **Slack review thread**    | Review cards show up to **3 prior customer messages** from the Meta thread (plus the current message under *Current message*), when `pageId` + `pageAccessToken` can fetch Graph history. `metadata.instagram_original_dm` remains the current message only. |
| **Thread backfill**        | On the **first** inbound for a `chatId` when the nanobot session has **no prior user history**, the channel fetches up to **20** prior customer messages from Graph (`/{pageId}/conversations?user_id=…`, with conversation-scan fallback). They are prefixed as `Instagram thread context before this message:` in model input; up to **5** most recent images from that history are attached. `metadata.instagram_original_dm` and Slack review cards still show only the **current** customer message. Backfill is skipped once the session has user messages or after one attempt per `chatId` (in-memory). Requires `SessionManager` (wired from channel manager when the gateway runs). |
| **Slack threading**        | One Slack thread per `chatId`; map persisted in `~/.nanobot/data/instagram_slack_threads.json` (`instagram_review_state`).                                                                                                                |
| **Startup**                | Requires `consentGranted`, Slack tokens, and at least one `accounts[]` entry. Webhook mode additionally requires per-account `appSecret` + `verifyToken`. Poll mode requires per-account `pageId` + `pageAccessToken`. Thread backfill uses the same per-account `pageId` + `pageAccessToken`.                    |

**Config example — single account (poll-first with webhooks off):**

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
          "appSecret": "secret-for-brand-main-app",
          "verifyToken": "verify-token-brand-main"
        },
        {
          "accountKey": "brand_outlet",
          "label": "Brand Outlet",
          "pageId": "222222222222222",
          "pageAccessToken": "EAAB...",
          "appSecret": "secret-for-brand-outlet-app",
          "verifyToken": "verify-token-brand-outlet"
        }
      ]
    }
  }
}
```

When `"useWebhook": true`, register Meta callbacks at `https://YOUR_PUBLIC_HOST/webhook/instagram/{accountKey}`. See [Config keys — `channels.instagram`](#channelsinstagram-channel-level) for the full key list.

### Instagram draft tool (`nanobot/agent/tools/instagram_draft.py`)

- Tool name: **`create_instagram_draft`**
- Parameters: `body` (required), `review_notes` (optional).
- Only works when session channel is `instagram`; otherwise returns an error string.
- Context-aware (`ContextAware`); uses session `chat_id` for draft handoff.

**Config:** no tool-specific keys — enable `channels.instagram` (above) and install `pip install -e '.[instagram]'`.

### Review state module (`nanobot/channels/instagram_review_state.py`)

In-memory draft queue (10-minute TTL) plus persisted Slack `thread_ts` per Instagram `chatId`. Keeps agent loop free of Instagram/Slack coupling.

### Repo tooling (no runtime config)

| Path                | Purpose                                                                                                                                      |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `.devcontainer/`    | Cursor/devcontainer image, firewall init (added in Prospr commit `881cba4b`).                                                                |
| `scripts/deploy.sh` | Rsync nanobot source to a remote host over SSH; optional systemd restart (`NANOBOT_DEPLOY_SYSTEMD_UNIT`, default `nanobot-gateway.service`). |

### Tests (fork-added or heavily extended)

- `tests/agent/test_loop_no_reply.py` — Slack read-only persist
- `tests/agent/test_unified_delivery.py` — unified session injection guard
- `tests/test_email_draft.py`, `tests/channels/test_email_channel.py` — SMTP/send disabled, IMAP IDLE
- `tests/test_instagram_channel.py`, `tests/test_instagram_draft_tool.py` — Instagram channel + draft tool

---

## Config keys

JSON uses **camelCase** aliases (Pydantic `to_camel`). Snake_case also accepted.

Fragments below merge into `~/.nanobot/config.json`. Longer setup runbooks: [`docs/prospr-customersupport-additions.md`](prospr-customersupport-additions.md), [`docs/instagram_multi_account_meta_setup.md`](instagram_multi_account_meta_setup.md).

### `agents.defaults` (upstream keys with fork behavior)

| Key                             | Type   | Default    | Fork behavior                                                                                                                                                                            |
| ------------------------------- | ------ | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `unifiedSession`                | bool   | `false`    | When `true`, mid-turn follow-ups only inject if delivery target matches active turn; see [Unified session](#unified-session-delivery-target-guard-unified_deliverypy).                   |
| `genericMemoryOnly`             | bool   | `false`    | Alternate Consolidator/Dream prompts for pattern-only memory; **cannot** combine with `eagerKnowledge.enabled`. See [Generic memory prompts](#generic-memory-prompts-genericmemoryonly). |
| `eagerKnowledge`                | object | —          | Fork-only; see [Eager knowledge](#eager-knowledge-non-unified-cross-channel-recall).                                                                                                     |
| `eagerKnowledge.enabled`        | bool   | `false`    | Promote session traffic into `memory/history.jsonl` soon after persist.                                                                                                                  |
| `eagerKnowledge.minBatch`       | int    | `3`        | LLM archive when pending chunk reaches this size.                                                                                                                                        |
| `eagerKnowledge.singletonIdleS` | int    | `120`      | Raw flush for smaller chunks after this idle time (seconds).                                                                                                                             |
| `eagerKnowledge.maxBatch`       | int    | `20`       | Max messages per eager flush.                                                                                                                                                            |
| `archiveMediaMaxBytes`          | int    | `10485760` | Max bytes read per attachment during `Consolidator.archive()` (eager + token consolidation).                                                                                             |
| `archiveExtractMaxChars`        | int    | `8000`     | Max inlined text per extracted document in archive prompts.                                                                                                                              |
| `archiveBootstrapMaxChars`      | int    | `12000`    | Max combined bootstrap reference block in archive system prompt.                                                                                                                         |
| `archiveMaxImages`              | int    | `5`        | Max vision image blocks per archive LLM call.                                                                                                                                            |

#### Example — `unifiedSession`

```json
{
  "agents": {
    "defaults": {
      "unifiedSession": true
    }
  }
}
```

#### Example — `eagerKnowledge`

```json
{
  "agents": {
    "defaults": {
      "unifiedSession": false,
      "eagerKnowledge": {
        "enabled": true,
        "minBatch": 3,
        "singletonIdleS": 120,
        "maxBatch": 20
      }
    }
  }
}
```

#### Example — `genericMemoryOnly`

```json
{
  "agents": {
    "defaults": {
      "genericMemoryOnly": true,
      "eagerKnowledge": { "enabled": false }
    }
  }
}
```

#### Example — Slack ambient context + eager promotion

Typical Prospr stack: persist non-mention channel traffic (`groupPolicy: "mention"`) and promote it into global history without a shared session:

```json
{
  "agents": {
    "defaults": {
      "unifiedSession": false,
      "eagerKnowledge": {
        "enabled": true,
        "minBatch": 3,
        "singletonIdleS": 120,
        "maxBatch": 20
      }
    }
  },
  "channels": {
    "slack": {
      "enabled": true,
      "botToken": "xoxb-...",
      "appToken": "xapp-...",
      "groupPolicy": "mention"
    }
  }
}
```

### `channels.slack` (upstream keys with fork behavior)

| Key           | Type   | Default     | Fork behavior                                                                                                                                                                                             |
| ------------- | ------ | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `groupPolicy` | string | `"mention"` | `"mention"` → non-mention channel messages use `no_reply` persist (see [Slack no_reply](#slack-persist-channel-traffic-without-replying-no_reply)). `"open"` → all channel messages get full agent turns. |

Other `channels.slack` keys (`botToken`, `appToken`, `replyInThread`, `groupAllowFrom`, `dm`, etc.) are unchanged upstream; see `SlackConfig` in `nanobot/channels/slack.py`.

#### Example — `groupPolicy` (fork `no_reply` persist)

```json
{
  "channels": {
    "slack": {
      "enabled": true,
      "botToken": "xoxb-...",
      "appToken": "xapp-...",
      "groupPolicy": "mention"
    }
  }
}
```

### `channels.email`

| Key                                                                                               | Type     | Default          | Notes                                                                                                                                  |
| ------------------------------------------------------------------------------------------------- | -------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `enabled`                                                                                         | bool     | `false`          |                                                                                                                                        |
| `consentGranted`                                                                                  | bool     | `false`          | Channel won’t start without explicit consent.                                                                                          |
| `imapHost`                                                                                        | string   | `""`             | Required when enabled.                                                                                                                 |
| `imapPort`                                                                                        | int      | `993`            |                                                                                                                                        |
| `imapUsername`                                                                                    | string   | `""`             |                                                                                                                                        |
| `imapPassword`                                                                                    | string   | `""`             | Gmail/Workspace: **App Password** only (16 letters after 2SV); not login password or `gmailDraft` OAuth token. `${ENV_VAR}` supported. |
| `imapMailbox`                                                                                     | string   | `"INBOX"`        |                                                                                                                                        |
| `imapUseSsl`                                                                                      | bool     | `true`           |                                                                                                                                        |
| `imapIdleEnabled`                                                                                 | bool     | `true`           | **Fork:** IDLE vs poll-only inbound.                                                                                                   |
| `pollIntervalSeconds`                                                                             | int      | `60`             | Clamped 5–60; used when IDLE off or as IDLE cycle cap.                                                                                 |
| `autoReplyEnabled`                                                                                | bool     | `true`           | **Not enforced** for send (outbound always blocked).                                                                                   |
| `sendProgress`                                                                                    | bool     | `true` (global)  | Per-channel override; set `false` on email to skip progress outbound.                                                                  |
| `outboundSlackChannel`                                                                            | string   | `""`             | **Fork:** Slack target for final agent replies (`#channel`, `C…`, `@user`). Requires `channels.slack.enabled`.                         |
| `markSeen`                                                                                        | bool     | `true`           |                                                                                                                                        |
| `maxBodyChars`                                                                                    | int      | `12000`          |                                                                                                                                        |
| `subjectPrefix`                                                                                   | string   | `"Re: "`         |                                                                                                                                        |
| `allowFrom`                                                                                       | string[] | `[]`             |                                                                                                                                        |
| `verifyDkim`                                                                                      | bool     | `true`           | Anti-spoofing on inbound.                                                                                                              |
| `verifySpf`                                                                                       | bool     | `true`           |                                                                                                                                        |
| `allowedAttachmentTypes`                                                                          | string[] | `[]`             | e.g. `["image/*"]` or `["*"]` to allow.                                                                                                |
| `maxAttachmentSize`                                                                               | int      | `2000000`        | Bytes per attachment.                                                                                                                  |
| `maxAttachmentsPerEmail`                                                                          | int      | `5`              |                                                                                                                                        |
| `smtpHost`, `smtpPort`, `smtpUsername`, `smtpPassword`, `smtpUseTls`, `smtpUseSsl`, `fromAddress` | various  | empty / defaults | Legacy schema fields; **outbound SMTP is not used**.                                                                                   |

#### Example — Gmail IMAP inbound (draft-only outbound)

Requires **2-Step Verification** + [App Password](https://myaccount.google.com/apppasswords) for Mail on `imapUsername`, and IMAP enabled in Gmail settings. Outbound replies use `tools.gmailDraft` (OAuth), not `imapPassword`.

```json
{
  "channels": {
    "email": {
      "enabled": true,
      "consentGranted": true,
      "imapHost": "imap.gmail.com",
      "imapPort": 993,
      "imapUsername": "support@yourcompany.com",
      "imapPassword": "${GMAIL_IMAP_APP_PASSWORD}",
      "imapUseSsl": true,
      "imapIdleEnabled": true,
      "pollIntervalSeconds": 60,
      "verifyDkim": true,
      "verifySpf": true,
      "allowFrom": ["*"]
    }
  }
}
```

On systemd, define `GMAIL_IMAP_APP_PASSWORD` in the unit or an `EnvironmentFile` loaded by the gateway service user, then restart the unit after config changes.

### `channels.instagram` (channel-level)

| Key                   | Type     | Default     | Notes                                                        |
| --------------------- | -------- | ----------- | ------------------------------------------------------------ |
| `enabled`             | bool     | `false`     |                                                              |
| `consentGranted`      | bool     | `false`     |                                                              |
| `streaming`           | bool     | `false`     |                                                              |
| `useWebhook`          | bool     | `true`      | `false` = poll-only inbound (no Meta HTTP callback).         |
| `pollFallbackEnabled` | bool     | `true`      | When `useWebhook` is true, also poll Graph on interval.      |
| `pollIntervalSeconds` | int      | `60`        | Clamped 5–60; must be > 0 for poll to run.                   |
| `slackBotToken`       | string   | `""`        | `xoxb-…`; scopes: `chat:write`, `chat:update`, `views.open`. |
| `slackDraftChannel`   | string   | `""`        | Slack channel ID (`C…`).                                     |
| `slackAppToken`       | string   | `""`        | `xapp-…`; Socket Mode scope `connections:write`.             |
| `webhookHost`         | string   | `"0.0.0.0"` | Meta Flask bind host.                                        |
| `webhookPort`         | int      | `5005`      | Meta Flask bind port.                                        |
| `allowFrom`           | string[] | `["*"]`     |                                                              |
| `accounts`            | object[] | `[]`        | Required; one entry per Instagram account (see below).       |

#### Example — single account (webhook + poll fallback)

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
          "pageId": "111111111111111",
          "pageAccessToken": "EAAB...",
          "appSecret": "your-meta-app-secret",
          "verifyToken": "your-random-verify-string"
        }
      ]
    }
  }
}
```

#### Example — poll-only inbound (no public Meta webhook yet)

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
          "pageAccessToken": "EAAB..."
        }
      ]
    }
  }
}
```

### `channels.instagram.accounts[]` (per account)

| Key               | Type   | Default | Notes                                                                                 |
| ----------------- | ------ | ------- | ------------------------------------------------------------------------------------- |
| `accountKey`      | string | `""`    | Stable id; webhook path segment and `chatId` prefix. Auto-set from `pageId` if empty. |
| `label`           | string | `""`    | Shown on Slack review cards.                                                          |
| `pageId`          | string | `""`    | Facebook Page ID; required for poll.                                                  |
| `pageAccessToken` | string | `""`    | Long-lived Page token; required for poll and send.                                    |
| `igUserId`        | string | `""`    | Optional; poll may skip messages from this IGSID.                                     |
| `appSecret`       | string | `""`    | Required when `useWebhook` is true.                                                   |
| `verifyToken`     | string | `""`    | Required when `useWebhook` is true; must match Meta dashboard.                        |

#### Example — multi-account `accounts[]`

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
          "pageId": "111111111111111",
          "pageAccessToken": "EAAB...",
          "igUserId": "",
          "appSecret": "secret-for-brand-main-app",
          "verifyToken": "verify-token-brand-main"
        },
        {
          "accountKey": "brand_outlet",
          "label": "Brand Outlet",
          "pageId": "222222222222222",
          "pageAccessToken": "EAAB...",
          "appSecret": "secret-for-brand-outlet-app",
          "verifyToken": "verify-token-brand-outlet"
        }
      ]
    }
  }
}
```

**Meta webhook URL (when `useWebhook` is true):**  
`https://YOUR_PUBLIC_HOST/webhook/instagram/{accountKey}`

**Runtime data file (not config):** `~/.nanobot/data/instagram_slack_threads.json` — Slack `thread_ts` per Instagram `chatId`.

---

## Agent expectations (workspace `AGENTS.md`)

- **Email:** Use `create_gmail_draft` for replies; never send mail directly.
- **Instagram:** Use `create_instagram_draft` when proposing a reply; omit it when no reply is needed; never send to Instagram directly.
- **Slack (mention mode):** Non-mention channel lines are stored for context only; the bot does not reply unless @mentioned (or in DM).

---

## Divergence from older internal docs

| Old doc claim                                                        | Actual code                                                             |
| -------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Slack interactivity via `POST /slack/actions` + `slackSigningSecret` | **Socket Mode only**; no signing secret config.                         |
| Tools under `nanobot/tools/`                                         | `nanobot/agent/tools/`                                                  |
| `instagram` extra includes Slack SDK                                 | Slack SDK is a main dependency; `instagram` extra is Flask only.        |
| Rely on `autoReplyEnabled: false` to block email send                | Send blocked in `EmailChannel.send()` regardless.                       |
| Non-mention Slack messages ignored                                   | **Persisted** to session with `no_reply` when `groupPolicy: "mention"`. |
