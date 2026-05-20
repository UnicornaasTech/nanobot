# Instagram Multi-Account Meta Configuration Guide

This runbook explains how to connect multiple Instagram accounts to the draft-review flow (Slack approval, human-triggered send only).

Each Instagram account should use its **own internal-use Meta app** (separate App Secret, verify token, and Page access token). Nanobot routes DMs by source account automatically.

## What You Will Configure

- Multiple Instagram Professional accounts (Business or Creator), each linked to a Facebook Page.
- One internal Meta Developer app **per** Instagram account (not one shared published app).
- One nanobot `channels.instagram.accounts` entry per account.
- Source-based routing: `chat_id = "{accountKey}:{customerSenderId}"`.

## Prerequisites

- Access to [Meta for Developers](https://developers.facebook.com/) and Business Manager for each brand/Page.
- Slack app tokens for draft review (`slackBotToken`, `slackAppToken`, `slackDraftChannel`).
- For **poll-first** rollout: Page ID + Page access token per account (no public webhook URL required yet).
- For **webhook** mode later: public HTTPS endpoint per account path (see below).

## Step-by-Step in Meta (repeat per account)

### 1) Verify account and Page links

1. Confirm the Instagram account is Professional (Business or Creator).
2. Confirm it is linked to the correct Facebook Page.
3. Confirm your Business Manager has access to that Page.

### 2) Create an internal-use Meta app (per account)

1. In [Meta for Developers](https://developers.facebook.com/apps/), create a new app for this account only.
2. Add Messenger / Instagram messaging products required by current Meta docs.
3. Note **App Secret** → `appSecret` on that account’s config entry.
4. Choose a random **Verify token** string → `verifyToken` on that account’s config entry.

### 3) Generate Page credentials (per account)

For the Page linked to this Instagram account, collect:

- `pageId` — Facebook Page ID
- `pageAccessToken` — long-lived Page token with Instagram messaging permissions
- `igUserId` — optional; helps poll mode skip self-sent messages
- `accountKey` — stable internal key (e.g. `brand_main`)
- `label` — human-readable name shown on Slack review cards

### 4) Webhooks (optional — phase 2)

When you enable `useWebhook: true`, register **this app’s** webhook for **this account only**:

- Callback URL: `https://YOUR_PUBLIC_HOST/webhook/instagram/{accountKey}`
  - Example: `https://api.example.com/webhook/instagram/brand_main`
- Verify token: must match that account’s `verifyToken` in config.
- Subscribe to `messages` (and fields Meta requires for Instagram DMs).
- Subscribe the Page to this app.

### 5) Validate Graph API access (per account)

```http
GET /{page-id}/conversations?platform=INSTAGRAM&access_token={pageAccessToken}
```

Expected: HTTP 200 and conversation data (no permission error).

## Nanobot config (poll-first recommended)

Set `useWebhook: false` to start with polling only. Each account still needs `pageId` and `pageAccessToken`.

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
          "igUserId": "1784...",
          "appSecret": "meta-app-secret-for-brand-main",
          "verifyToken": "random-verify-token-brand-main"
        },
        {
          "accountKey": "brand_outlet",
          "label": "Brand Outlet",
          "pageId": "222222222222222",
          "pageAccessToken": "EAAB...",
          "igUserId": "1784...",
          "appSecret": "meta-app-secret-for-brand-outlet",
          "verifyToken": "random-verify-token-brand-outlet"
        }
      ]
    }
  }
}
```

## Routing behavior

- Inbound DMs are tagged with the source `accountKey`.
- Conversation id: `{accountKey}:{customerSenderId}` (prevents collisions when the same customer messages two brands).
- Slack review cards show the account label.
- Send / Edit & Send uses the same account’s Page access token.

## Verification checklist

1. Set `useWebhook: false`, start nanobot gateway, confirm poll log lists all `accountKey` values.
2. Send a test DM to each Instagram account.
3. Confirm separate Slack threads/cards per account (and per customer).
4. Approve send on each card; confirm replies appear from the correct Instagram account.
5. (Optional) Enable webhooks per account and test `GET`/`POST` on `/webhook/instagram/{accountKey}`.

## Common failures

| Symptom | Likely cause |
|--------|----------------|
| `401` on webhook POST | Wrong `appSecret` for that account’s app |
| No events for one account | Page not subscribed to that account’s Meta app |
| Send fails for one account only | Expired `pageAccessToken` for that entry |
| Wrong account replies | Missing or wrong `account_key` in Slack action payload (upgrade if using old cards) |
| Cross-account thread mixing | Old config without namespaced `chat_id` — restart after upgrade |

## Security notes

- Store each account’s `pageAccessToken` and `appSecret` in a secret manager.
- Rotate tokens after access changes.
- Do not log full tokens.
