FROM debian:bookworm-slim

# Minimal runtime dependencies for the agent CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
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

# `agy` is the Antigravity CLI. The repo ships a graceful shim (see ./agy) so the image always builds;
# drop the real proprietary binary here to replace it, or mount it over /usr/local/bin/agy at runtime.
COPY agy /usr/local/bin/agy
RUN chmod 755 /usr/local/bin/agy

ENV PATH="/home/agent/.local/bin:/usr/local/bin:/usr/bin:/bin"
ENV HOME="/home/agent"

USER 10001:10001
WORKDIR /workspace

# Keep container running as an isolated daemon; work happens via `docker exec`.
CMD ["tail", "-f", "/dev/null"]
