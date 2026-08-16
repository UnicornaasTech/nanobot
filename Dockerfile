FROM node:24-bookworm-slim AS webui-builder

WORKDIR /app
COPY webui/package.json webui/package-lock.json ./webui/
WORKDIR /app/webui
RUN npm ci
COPY webui/ ./
RUN mkdir -p /app/nanobot/web && npm run build

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates git bubblewrap openssh-client libmagic1 \
        curl gnupg \
        chromium \
        libatk1.0-0 \
        libdbus-1-3 \
        libcups2 \
        libatk-bridge2.0-0 \
        libnspr4 \
        libnss3 \
        libnss3-tools && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends nodejs && \
    apt-get purge -y gnupg && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# agent-browser CLI for headless web automation (uses system Chromium)
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
RUN npm install -g agent-browser && \
    mv /usr/local/share/npm-global/bin/agent-browser /usr/local/share/npm-global/bin/agent-browser-real && \
    printf '#!/usr/bin/env bash\nexec /usr/local/share/npm-global/bin/agent-browser-real --executable-path /usr/bin/chromium "$@"\n' > /usr/local/share/npm-global/bin/agent-browser && \
    chmod +x /usr/local/share/npm-global/bin/agent-browser

WORKDIR /app

# Keep the runtime environment writable by the non-root nanobot user. Enabled
# channels may install their manifest-declared dependencies at startup.
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:/usr/local/share/npm-global/bin:$PATH"
RUN uv venv --seed "$VIRTUAL_ENV"

# Install Python dependencies first (cached layer). Hatch reads the custom build
# hook from hatch_build.py even for this metadata-only install.
ARG NANOBOT_EXTRAS=
# FORK: opt-in web-guard extras (CliGuard / torch). Default false keeps images slim.
ARG WEB_GUARD=false
ENV UV_HTTP_TIMEOUT=600
COPY pyproject.toml README.md LICENSE THIRD_PARTY_NOTICES.md hatch_build.py ./
RUN mkdir -p nanobot && touch nanobot/__init__.py && \
    extras="${NANOBOT_EXTRAS}" && \
    case "$(printf '%s' "$WEB_GUARD" | tr '[:upper:]' '[:lower:]')" in \
      1|true|yes|on) \
        if [ -n "$extras" ]; then extras="${extras},web-guard"; else extras="web-guard"; fi ;; \
    esac && \
    if echo ",${extras}," | grep -q ',web-guard,'; then \
      export UV_INDEX_URL=https://download.pytorch.org/whl/cpu \
        UV_EXTRA_INDEX_URL=https://pypi.org/simple; \
    fi && \
    if [ -n "$extras" ]; then \
        NANOBOT_SKIP_WEBUI_BUILD=1 uv pip install \
            --python "$VIRTUAL_ENV/bin/python" --no-cache ".[${extras}]"; \
    else \
        NANOBOT_SKIP_WEBUI_BUILD=1 uv pip install \
            --python "$VIRTUAL_ENV/bin/python" --no-cache .; \
    fi && \
    rm -rf nanobot

# Copy the full source and install
COPY nanobot/ nanobot/
COPY scripts/install_channel_dependencies.py scripts/
COPY --from=webui-builder /app/nanobot/web/dist/ nanobot/web/dist/
ARG WEB_GUARD=false
ARG NANOBOT_EXTRAS=
RUN extras="${NANOBOT_EXTRAS}" && \
    case "$(printf '%s' "$WEB_GUARD" | tr '[:upper:]' '[:lower:]')" in \
      1|true|yes|on) \
        if [ -n "$extras" ]; then extras="${extras},web-guard"; else extras="web-guard"; fi ;; \
    esac && \
    if echo ",${extras}," | grep -q ',web-guard,'; then \
      export UV_INDEX_URL=https://download.pytorch.org/whl/cpu \
        UV_EXTRA_INDEX_URL=https://pypi.org/simple; \
    fi && \
    if [ -n "$extras" ]; then \
        NANOBOT_SKIP_WEBUI_BUILD=1 uv pip install \
            --python "$VIRTUAL_ENV/bin/python" --no-cache ".[${extras}]"; \
    else \
        NANOBOT_SKIP_WEBUI_BUILD=1 uv pip install \
            --python "$VIRTUAL_ENV/bin/python" --no-cache .; \
    fi

# Preinstall selected channel dependencies from their manifests. A comma-separated
# list keeps the image configurable while preserving WhatsApp in the default image.
ARG NANOBOT_CHANNELS=whatsapp
RUN for channel in $(printf '%s' "$NANOBOT_CHANNELS" | tr ',' ' '); do \
        python -m scripts.install_channel_dependencies "$channel"; \
    done

# Render deploy template (see render.yaml): committed gateway config that wires
# secrets through ${ANTHROPIC_API_KEY} / ${NANOBOT_WEB_TOKEN} env vars (resolved
# at startup). Lives in the code dir (/app), not the data dir, so a mounted disk
# won't shadow it. Only used when RENDER=true; ignored by local runs.
COPY render-config.json ./

# Create the non-root user and hand ownership of the writable virtualenv to it.
RUN useradd -m -u 1000 -s /bin/bash nanobot && \
    mkdir -p /home/nanobot/.nanobot && \
    chown -R nanobot:nanobot /home/nanobot /app/.venv

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh && chmod +x /usr/local/bin/entrypoint.sh

# FORK: container egress firewall (optional at runtime via NANOBOT_INIT_FIREWALL=1)
COPY init-firewall.sh /usr/local/bin/init-firewall.sh
RUN sed -i 's/\r$//' /usr/local/bin/init-firewall.sh && chmod +x /usr/local/bin/init-firewall.sh && \
    apt-get update && apt-get install -y --no-install-recommends sudo iptables ipset && \
    rm -rf /var/lib/apt/lists/* && \
    echo "nanobot ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh" > /etc/sudoers.d/nanobot-firewall && \
    chmod 0440 /etc/sudoers.d/nanobot-firewall

# Start as root so the entrypoint can chown the data dir (on Render, the
# freshly-mounted root-owned persistent disk) before dropping to the non-root
# nanobot user via setpriv. The entrypoint drops privileges on every root start
# and fails closed if it cannot, so the agent never runs as root (see
# entrypoint.sh).
USER root
ENV HOME=/home/nanobot
# Ensure crash output reaches Render logs (app output is otherwise swallowed on
# non-graceful exit).
ENV PYTHONUNBUFFERED=1 PYTHONFAULTHANDLER=1

# Gateway health endpoint and optional WebUI/WebSocket channel ports
EXPOSE 18790 8765

ENTRYPOINT ["entrypoint.sh"]
CMD ["status"]
