# Fork changes vs upstream (HKUDS/nanobot)

Upstream: https://github.com/HKUDS/nanobot · Fork: https://github.com/prospr-app/nanobot-prospr

**Upstream baseline:** `public/main` @ `d2da6df1` (merged 2026-06-23; re-integrated 2026-08-15).

## Prospr-only

See [prospr-custom-implementations.md](prospr-custom-implementations.md) for the full list (Slack `no_reply`, eager knowledge, Instagram/Gmail, unified-session delivery guard, MCP/tool-repeat guards, email send disabled, etc.).

## No longer fork-only

- **Max-iterations finalization** — uses upstream `finalize_on_max_iterations` and `build_budget_exhausted_finalization_message` in `nanobot/agent/runner.py`.
- **Empty-response handling** — uses upstream same-model `_MAX_EMPTY_RETRIES` + finalization retry in `runner.py` (no fork `fallbackModels`-on-blank-success path).
- **Dream prompts** — single-phase upstream `agent/dream.md` (former fork `genericMemoryOnly` alternate prompts removed).
