FROM debian:bookworm-slim

# Install system dependencies
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

# Create directories
RUN mkdir -p /root/.local/bin /root/.gemini/antigravity-cli /workspace
ENV PATH="/root/.local/bin:/usr/local/bin:$PATH"
ENV HOME="/root"

WORKDIR /workspace

# Keep container running as an isolated daemon
CMD ["tail", "-f", "/dev/null"]
