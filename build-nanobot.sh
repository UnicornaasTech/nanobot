#!/bin/sh
# Rebuild Docker images after local code changes.
# start-nanobot.sh runs the existing image and does not rebuild automatically.
#
# Usage:
#   ./build-nanobot.sh [web-guard|no-web-guard] [docker compose build args...]
#
# Default: no web-guard (WEB_GUARD=false). Pass web-guard to install CliGuard/torch.
# When building without web-guard, set NANOBOT_WEB_FETCH_GUARD=0 in .env at runtime.
set -e

WEB_GUARD=false

if [ $# -gt 0 ]; then
  case "$1" in
    no-web-guard|without-web-guard|--no-web-guard|slim)
      WEB_GUARD=false
      echo "Building without web-guard (default)."
      echo "Add NANOBOT_WEB_FETCH_GUARD=0 to .env if you have not already."
      shift
      ;;
    web-guard|with-web-guard|--web-guard)
      WEB_GUARD=true
      echo "Building with web-guard extras."
      shift
      ;;
  esac
fi

export WEB_GUARD
docker compose build --build-arg "WEB_GUARD=${WEB_GUARD}" nanobot-gateway "$@"
