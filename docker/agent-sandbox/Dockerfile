FROM debian:bookworm-slim

# Minimal runtime dependencies for the agent CLI. bsdutils provides script(1), which gives the CLI a
# pseudo-terminal for its interactive sign-in (AIE relays the sign-in link and code through it).
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    bsdutils \
    curl \
    ca-certificates \
    git \
    procps \
    python3 \
    tar \
    gzip \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged user. The agent never runs as root.
RUN groupadd --gid 10001 agent \
    && useradd --uid 10001 --gid 10001 --home-dir /home/agent --create-home --shell /usr/sbin/nologin agent \
    && mkdir -p /home/agent/.gemini/antigravity-cli /home/agent/.local/bin /workspace \
    && chown -R agent:agent /home/agent /workspace \
    && chmod 700 /home/agent /home/agent/.gemini

# Fallback: a graceful shim (see ./agy) so the image always builds, even offline. It prints no
# version, which is how AIE tells it apart from the real CLI.
COPY agy /usr/local/bin/agy
RUN chmod 755 /usr/local/bin/agy

# The Antigravity CLI from Google's official installer. It is installed under /opt/agy (root-owned,
# read-only at runtime) and linked into /usr/local/bin, so the per-user home (a volume at runtime)
# never hides it. If the download or install fails, the build continues with the shim and AIE shows
# why the agent is unavailable. Build with --build-arg AGY_INSTALL=0 to skip it.
ARG AGY_INSTALL=1
ARG AGY_INSTALL_URL=https://antigravity.google/cli/install.sh
RUN set -eu; \
    if [ "$AGY_INSTALL" != "1" ]; then echo "AGY_INSTALL=$AGY_INSTALL: keeping the shim"; exit 0; fi; \
    mkdir -p /opt/agy; \
    if curl -fsSL --retry 3 --connect-timeout 20 "$AGY_INSTALL_URL" -o /tmp/agy-install.sh \
       && HOME=/opt/agy SHELL=/bin/bash bash /tmp/agy-install.sh </dev/null; then \
      bin=""; \
      for c in /opt/agy/.local/bin/agy /opt/agy/bin/agy; do \
        if [ -e "$c" ]; then bin="$(readlink -f "$c")"; break; fi; \
      done; \
      if [ -z "$bin" ]; then bin="$(find /opt/agy -type f -name agy -perm -u+x | head -n 1)"; fi; \
      if [ -n "$bin" ] && "$bin" --version; then \
        chmod -R a+rX /opt/agy; \
        ln -sf "$bin" /usr/local/bin/agy; \
        echo "Antigravity CLI installed: $bin"; \
      else \
        echo "WARNING: the Antigravity CLI installer finished but left no working agy binary; keeping the shim." >&2; \
      fi; \
    else \
      echo "WARNING: could not download or run $AGY_INSTALL_URL; keeping the shim (rebuild with network access)." >&2; \
    fi; \
    rm -f /tmp/agy-install.sh

ENV PATH="/home/agent/.local/bin:/usr/local/bin:/usr/bin:/bin"
ENV HOME="/home/agent"

USER 10001:10001
WORKDIR /workspace

# Keep container running as an isolated daemon; work happens via `docker exec`.
CMD ["tail", "-f", "/dev/null"]
