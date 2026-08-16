#!/bin/sh
# Start gateway (Matrix/channels, health :18790, WebUI WS :8765).
# Runs with debug/verbose logging (-v). Ctrl-C stops both.
# Rebuild after code changes: ./build-nanobot.sh
set -e
debug_compose=$(mktemp)
trap 'rm -f "$debug_compose"' EXIT
cat > "$debug_compose" <<'EOF'
services:
  nanobot-gateway:
    command: ["gateway", "-v"]
EOF
exec docker compose \
  -f docker-compose.yml \
  -f docker-compose.override.yml \
  -f "$debug_compose" \
  up nanobot-gateway
