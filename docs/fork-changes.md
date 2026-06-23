# Fork changes vs upstream (HKUDS/nanobot)

Upstream: https://github.com/HKUDS/nanobot · Fork: https://github.com/prospr-app/nanobot-prospr

**Upstream baseline:** `public/main` @ `d2da6df1` (merged 2026-06-23).

## Prospr-only

See [prospr-custom-implementations.md](prospr-custom-implementations.md) for the full list (Slack `no_reply`, eager knowledge, Instagram/Gmail, unified-session delivery guard, MCP/tool-repeat guards, `genericMemoryOnly`, email send disabled, etc.).

## No longer fork-only

- **Max-iterations finalization** — now uses upstream `finalize_on_max_iterations` and `build_budget_exhausted_finalization_message` in `nanobot/agent/runner.py`.
