#!/bin/sh
set -eu
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"
node scripts/preview.mjs stop < /dev/null 2>/dev/null || true
if curl -sf -o /dev/null --max-time 2 http://127.0.0.1:8080/ 2>/dev/null || cmd.exe /c "curl -sf -o NUL --max-time 2 http://localhost:8080/" < /dev/null 2>/dev/null; then
  exit 0
fi
if command -v docker >/dev/null 2>&1; then
  # Background: the first run builds the sandbox image (downloads the agent CLI), which takes minutes.
  nohup docker compose -f docker-compose.agent-sandbox.yml up -d < /dev/null > /dev/null 2>&1 &
fi
nohup npm run dev < /dev/null >>/tmp/app-startup.log 2>&1 &
