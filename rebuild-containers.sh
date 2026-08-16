#!/bin/sh
# Rebuild gateway and API images. WEB_GUARD defaults to false (matches Dockerfile).
# Opt in: WEB_GUARD=true ./rebuild-containers.sh
WEB_GUARD=${WEB_GUARD:-false}
export WEB_GUARD
docker compose build --build-arg "WEB_GUARD=${WEB_GUARD}" nanobot-gateway
docker compose build --build-arg "WEB_GUARD=${WEB_GUARD}" nanobot-api
