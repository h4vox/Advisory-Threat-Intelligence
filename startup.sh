#!/bin/sh
# Brings AIE up after a (re)boot: the local databases, the agent sandbox, then the app.
#
#   AIE_RUN_MODE=production (default)  the built app (`npm run start:prod`): fast to load. It is
#                                       rebuilt first when the code changed since the last build.
#   AIE_RUN_MODE=dev                    the Vite dev server (`npm run dev`): live reload, slow to load.
#
# Settings come from the environment or .env (AIE_RUN_MODE, AIE_HOST, PORT). Returns at once; the
# build and the server run in the background (logs: /tmp/app-build.log, /tmp/app-startup.log).
set -eu
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

# A value from the environment, else from .env, else the default.
setting() {
  eval "current=\${$1:-}"
  if [ -n "$current" ]; then printf '%s' "$current"; return; fi
  if [ -f .env ]; then
    value="$(grep -E "^[[:space:]]*$1=" .env | tail -n 1 | cut -d= -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/")"
    if [ -n "$value" ]; then printf '%s' "$value"; return; fi
  fi
  printf '%s' "$2"
}

PORT="$(setting PORT 8080)"
RUN_MODE="$(setting AIE_RUN_MODE production)"
# Keeps today's reachability (all interfaces). Behind a reverse proxy on this machine, set
# AIE_HOST=127.0.0.1 in .env so the app is reachable only through the proxy.
AIE_HOST="$(setting AIE_HOST 0.0.0.0)"
export PORT AIE_HOST

node scripts/preview.mjs stop < /dev/null 2>/dev/null || true
if curl -sf -o /dev/null --max-time 2 "http://127.0.0.1:${PORT}/login" 2>/dev/null; then
  exit 0
fi

if command -v docker >/dev/null 2>&1; then
  # Local database services: PostgreSQL and the interim MongoDB.
  if [ -f docker-compose.db.yml ]; then
    nohup docker compose -f docker-compose.db.yml --profile interim-mongo up -d < /dev/null > /dev/null 2>&1 &
  fi
  # Background: the first run builds the sandbox image (downloads the agent CLI), which takes minutes.
  nohup docker compose -f docker-compose.agent-sandbox.yml up -d < /dev/null > /dev/null 2>&1 &
fi

export NODE_OPTIONS="${NODE_OPTIONS:---max-old-space-size=768}"

# Dependencies: install when the lockfile changed since the last install (e.g. after a pull that
# added a package), so the app never starts against missing modules.
if [ ! -f node_modules/.package-lock.json ] || [ package-lock.json -nt node_modules/.package-lock.json ]; then
  echo "[startup] installing dependencies ($(date))" >>/tmp/app-build.log
  npm install --no-audit --no-fund >>/tmp/app-build.log 2>&1 || echo "[startup] npm install failed; see /tmp/app-build.log" >>/tmp/app-build.log
fi

if [ "$RUN_MODE" = "dev" ]; then
  nohup npm run dev < /dev/null >>/tmp/app-startup.log 2>&1 &
  exit 0
fi

# Production: build when there is no build yet, or the code changed since it was made.
nohup sh -c '
  needs_build=0
  if [ ! -f .output/server/index.mjs ]; then
    needs_build=1
  elif [ -n "$(find src server scripts migrations package.json package-lock.json vite.config.ts -newer .output/server/index.mjs -type f 2>/dev/null | head -n 1)" ]; then
    needs_build=1
  fi
  if [ "$needs_build" = 1 ]; then
    echo "[startup] building the production app ($(date))"
    if ! NODE_OPTIONS="--max-old-space-size=${AIE_BUILD_HEAP_MB:-2048}" npm run build; then
      echo "[startup] build failed; starting the dev server instead (see the errors above)"
      exec npm run dev
    fi
  fi
  exec npm run start:prod
' < /dev/null >>/tmp/app-build.log 2>&1 &
exit 0
