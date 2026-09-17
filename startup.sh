#!/bin/sh
set -eu
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"
node scripts/preview.mjs stop < /dev/null 2>/dev/null || true
if curl -sf -o /dev/null --max-time 2 http://127.0.0.1:8080/; then
  exit 0
fi
if command -v docker >/dev/null 2>&1; then
  docker compose -f docker-compose.agent-sandbox.yml up -d < /dev/null 2>/dev/null || true
fi
nohup npm run dev < /dev/null >>/tmp/app-startup.log 2>&1 &
