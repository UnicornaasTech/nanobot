#!/bin/sh
# Stop gateway and API containers started by start-nanobot.sh.
set -e
cd "$(dirname "$0")"
docker compose \
  -f docker-compose.yml \
  -f docker-compose.override.yml \
  stop nanobot-gateway nanobot-api
