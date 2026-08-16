#!/bin/sh
WEB_GUARD=${WEB_GUARD:-false}
export WEB_GUARD
docker compose build --build-arg "WEB_GUARD=${WEB_GUARD}" nanobot-gateway nanobot-api "$@"
