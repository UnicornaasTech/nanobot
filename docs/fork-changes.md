# Fork changes vs upstream (HKUDS/nanobot)

NOTE: To verify a Matrix device, just put recoveryKey to config (see below)

Upstream: https://github.com/HKUDS/nanobot · Fork: https://github.com/UnicornaasTech/nanobot · Prospr source: https://github.com/prospr-app/nanobot-prospr

**Upstream baseline:** `public/main` @ `d2da6df1` (merged 2026-06-23; re-integrated via Prospr 2026-08-15).

## UnicornaasTech-only

- **Web fetch guard** — `nanobot/contrib/web_guard/` patches `web_fetch` post-fetch with local CliGuard (default) or Prompt Guard 2; config: `web-fetch-guard.json`; debug timing logs per page/chunk when gateway/API run with `-v` (e.g. `./start-nanobot.sh`)
- **Matrix device verification** — cross-signing via `recoveryKey` / `recoveryPassphrase` at startup (Ed25519 via `cryptography`, no libolm); SAS accepts the bot's own MXID, answers Element `m.key.verification.request` with `ready`, and patches nio 0.26 SAS commitments to unpadded base64 (Element interop)
- **Matrix native voice messages** — MSC3245 voice delivery via `OutboundMessage.metadata._matrix_voice` and `message(..., voice=true)` (`nanobot/channels/matrix/voice.py`)
- **MCP transport-timeout resilience** — SSE read-timeout cleared; httpx transport failures reset the server via `MCPProvider.reset_after_transport_failure` (`nanobot/agent/tools/mcp.py`)
- **Container deployment** — image always includes `agent-browser` (Chromium-backed CLI); **web-guard is opt-in at build** (`WEB_GUARD=true` / `./build-nanobot.sh web-guard`, default `false`); host `HF_HOME` cache mounted; host ttswrapper output (`TTS_OUTPUT_HOST`) mounted at `workspace/media/tts`; host spotify-mcp (`SPOTIFY_MCP_HOST`) mounted at `/home/nanobot/tools/spotify-mcp`; secrets via gitignored `.env` + `${VAR}` in config; firewall bootstrap (`init-firewall.sh`, `NANOBOT_INIT_FIREWALL=1` in `docker-compose.override.yml`); inbound TCP 8765/18790/8900; outbound to `host.docker.internal` allows TCP 2022 (Whisper STT), 2023 (TTS MCP), 8801–8810, and 18000 (local LLM)

Details: [web fetch guard](fork/web-guard.md)

## From Prospr fork (merged)

See [prospr-custom-implementations.md](prospr-custom-implementations.md) for the full list (Slack `no_reply`, eager knowledge, Instagram/Gmail, unified-session delivery guard, MCP/tool-repeat guards, email send disabled, email IMAP IPv4-only connect, etc.).

## No longer fork-only

- **Max-iterations finalization** — uses upstream `finalize_on_max_iterations` and `build_budget_exhausted_finalization_message` in `nanobot/agent/runner.py`.
- **Empty-response handling** — uses upstream same-model `_MAX_EMPTY_RETRIES` + finalization retry in `runner.py` (no fork `fallbackModels`-on-blank-success path).
- **Dream prompts** — single-phase upstream `agent/dream.md` (former fork `genericMemoryOnly` alternate prompts removed).
- **Repeated tool-batch guard** — upstream/prospr fingerprinting in `nanobot/utils/runtime.py` and `nanobot/agent/runner.py`.
