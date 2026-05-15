FROM node:20

ARG TZ
ENV TZ="$TZ"

# Install basic development tools and iptables/ipset
# Use PostgreSQL upstream apt repo to install pg client v18 (matches Postgres.app 18.x)
RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  curl \
  gnupg2 \
  && install -d -m 0755 /etc/apt/keyrings \
  && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
  | gpg --dearmor -o /etc/apt/keyrings/postgresql.gpg \
  && chmod a+r /etc/apt/keyrings/postgresql.gpg \
  && echo "deb [signed-by=/etc/apt/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" \
  > /etc/apt/sources.list.d/pgdg.list \
  && apt-get update && apt-get install -y --no-install-recommends \
  less \
  strace \
  git \
  procps \
  sudo \
  fzf \
  zsh \
  man-db \
  unzip \
  gh \
  watchman \
  iptables \
  ipset \
  iproute2 \
  dnsutils \
  aggregate \
  jq \
  libatk1.0-0 \
  libdbus-1-3 \
  libcups2 \
  libatk-bridge2.0-0 \
  libnspr4 \
  chromium \
  nano \
  vim \
  locales \
  libnss3 \
  libnss3-tools \
  postgresql-client-18 \
  python3 \
  ripgrep \
  lsof \
  netcat-openbsd \
  util-linux \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

# Generate locale
RUN sed -i '/en_US.UTF-8/s/^# //g' /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8


# FLUTTER SPECIFICS
# Install Flutter (system-wide) and set ownership for node user
#RUN git clone https://github.com/flutter/flutter.git -b stable /opt/flutter && \
#  chown -R node:node /opt/flutter
#ENV PATH="/opt/flutter/bin:$PATH"

# Configure git safe.directory for Flutter (as node user)
#USER node
#RUN git config --global --add safe.directory /opt/flutter

# Pre-download Flutter dependencies (as node user who owns the directory)
#USER node
#RUN flutter precache
#USER root

# Ensure default node user has access to /usr/local/share
RUN mkdir -p /usr/local/share/npm-global && \
  chown -R node:node /usr/local/share

ARG USERNAME=node

# Persist bash history.
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
  && mkdir /commandhistory \
  && touch /commandhistory/.bash_history \
  && chown -R $USERNAME /commandhistory

# Set `DEVCONTAINER` environment variable to help with orientation
ENV DEVCONTAINER=true

# Create workspace directory and set permissions
RUN mkdir -p /workspace && \
  chown -R node:node /workspace

WORKDIR /workspace

ARG GIT_DELTA_VERSION=0.18.2
RUN ARCH=$(dpkg --print-architecture) && \
  wget "https://github.com/dandavison/delta/releases/download/${GIT_DELTA_VERSION}/git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" && \
  sudo dpkg -i "git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb" && \
  rm "git-delta_${GIT_DELTA_VERSION}_${ARCH}.deb"

# Set up non-root user
USER node

# Cursor CLI (agent) for orchestrator / headless runs; auth via CURSOR_API_KEY
RUN curl -fsSL https://cursor.com/install | bash
ENV PATH="/home/node/.local/bin:/usr/local/share/npm-global/bin:$PATH"

# Install global packages
ENV NPM_CONFIG_PREFIX=/usr/local/share/npm-global
RUN npm install -g agent-browser
RUN mv /usr/local/share/npm-global/bin/agent-browser /usr/local/share/npm-global/bin/agent-browser-real && \
  printf '#!/usr/bin/env bash\nexec /usr/local/share/npm-global/bin/agent-browser-real --executable-path /usr/bin/chromium "$@"\n' > /usr/local/share/npm-global/bin/agent-browser && \
  chmod +x /usr/local/share/npm-global/bin/agent-browser

# Set the default shell to zsh rather than sh
ENV SHELL=/bin/zsh

# Set the default editor and visual
ENV EDITOR=nano
ENV VISUAL=nano

# Default powerline10k theme
#ARG ZSH_IN_DOCKER_VERSION=1.2.0
#RUN sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v${ZSH_IN_DOCKER_VERSION}/zsh-in-docker.sh)" -- \
#  -p git \
#  -p fzf \
#  -a "source /usr/share/doc/fzf/examples/key-bindings.zsh" \
#  -a "source /usr/share/doc/fzf/examples/completion.zsh" \
#  -a "export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
#  -x


# Copy and set up firewall script
COPY init-firewall.sh /usr/local/bin/
USER root
RUN chmod +x /usr/local/bin/init-firewall.sh && \
  echo "node ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh" > /etc/sudoers.d/node-firewall && \
  chmod 0440 /etc/sudoers.d/node-firewall
USER node
