#!/usr/bin/env bash
# Deploy nanobot source to a remote host via rsync over SSH.
#
# Usage:
#   ./scripts/deploy.sh <ssh-target> [remote-dir]
#
# <ssh-target> is any host spec ssh/rsync accept: an SSH config Host alias
# (e.g. "my-bot-vm") or user@hostname.
#
# Examples:
#   ./scripts/deploy.sh my-bot-vm
#   ./scripts/deploy.sh my-bot-vm /opt/nanobot
#   ./scripts/deploy.sh user@10.0.0.5 ~/nanobot --restart
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SSH_TARGET=""
REMOTE_DIR=""
SYSTEMD_UNIT="${NANOBOT_DEPLOY_SYSTEMD_UNIT:-nanobot-gateway.service}"
DO_RESTART=false
DO_DRY_RUN=false
DO_DELETE=false

usage() {
  cat <<'EOF'
Deploy nanobot source to a remote host via rsync over SSH.

Usage:
  ./scripts/deploy.sh <ssh-target> [remote-dir] [options]

<ssh-target> is any host spec ssh/rsync accept: an SSH config Host alias
(e.g. "my-bot-vm") or user@hostname.

Examples:
  ./scripts/deploy.sh my-bot-vm
  ./scripts/deploy.sh my-bot-vm /opt/nanobot
  ./scripts/deploy.sh user@10.0.0.5 ~/nanobot

Options:
  --restart       Restart systemd user unit after deploy (see NANOBOT_DEPLOY_SYSTEMD_UNIT)
  --dry-run       Pass --dry-run to rsync (no remote changes)
  --delete        Remove remote files absent locally (rsync --delete)
  -h, --help      Show this help

Environment:
  NANOBOT_DEPLOY_DIR            Default remote directory (default: ~/nanobot)
  NANOBOT_DEPLOY_SYSTEMD_UNIT   systemd --user unit to restart (default: nanobot-gateway.service)
EOF
}

log() {
  printf '==> %s\n' "$*"
}

die() {
  printf 'deploy: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    --dry-run)
      DO_DRY_RUN=true
      shift
      ;;
    --delete)
      DO_DELETE=true
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      die "unknown option: $1 (try --help)"
      ;;
    *)
      if [[ -z "$SSH_TARGET" ]]; then
        SSH_TARGET="$1"
      elif [[ -z "$REMOTE_DIR" ]]; then
        REMOTE_DIR="$1"
      else
        die "unexpected argument: $1"
      fi
      shift
      ;;
  esac
done

[[ -n "$SSH_TARGET" ]] || {
  usage >&2
  die "missing required <ssh-target>"
}

REMOTE_DIR="${REMOTE_DIR:-${NANOBOT_DEPLOY_DIR:-~/nanobot}}"
REMOTE_DIR="${REMOTE_DIR%/}"

RSYNC_OPTS=(
  -avz
  --human-readable
  --exclude '.git'
  --exclude '.venv'
  --exclude 'venv'
  --exclude '__pycache__'
  --exclude '*.pyc'
  --exclude '.pytest_cache'
  --exclude '.mypy_cache'
  --exclude '.ruff_cache'
  --exclude 'dist'
  --exclude 'build'
  --exclude '*.egg-info'
  --exclude '.coverage'
  --exclude 'htmlcov'
  --exclude 'coverage'
  --exclude '.env'
  --exclude '.worktrees'
  --exclude '.worktree'
  --exclude '.cursor'
  --exclude '.vscode'
  --exclude '.idea'
  --exclude '.DS_Store'
  --exclude 'webui/node_modules'
  --exclude 'webui/dist'
  --exclude 'webui/coverage'
  --exclude 'webui/.vite'
  --exclude 'bridge/node_modules'
  --exclude 'bridge/dist'
)

if $DO_DRY_RUN; then
  RSYNC_OPTS+=(--dry-run)
fi

if $DO_DELETE; then
  RSYNC_OPTS+=(--delete)
fi

DEST="${SSH_TARGET}:${REMOTE_DIR}/"

log "Source:      $REPO_ROOT"
log "Destination: $DEST"
if $DO_DRY_RUN; then
  log "Mode:        dry-run"
fi

rsync "${RSYNC_OPTS[@]}" "$REPO_ROOT/" "$DEST"

log "Done."
