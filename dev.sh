#!/usr/bin/env bash
# Start Prahari for local development: the Go API on :8000, then the Vite
# frontend on :5173 once the API answers. Ctrl+C stops both.
#
#   ./dev.sh            # SQLite in backend/prahari.db, demo data seeded on first run
#   ./dev.sh --fresh    # delete the local database first
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
API_PORT=8000

if [ "${1:-}" = "--fresh" ]; then
  rm -f "$ROOT/backend/prahari.db" "$ROOT/backend/prahari.db-wal" "$ROOT/backend/prahari.db-shm"
  echo "Local database removed; the demo will be seeded again."
fi

if lsof -ti "tcp:$API_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "Port $API_PORT is already in use. Stop that process first:  lsof -ti tcp:$API_PORT | xargs kill"
  exit 1
fi

for tool in go npm; do
  command -v "$tool" >/dev/null || { echo "$tool is not installed or not on PATH."; exit 1; }
done
[ -d "$ROOT/frontend/node_modules" ] || (cd "$ROOT/frontend" && npm install)

cleanup() {
  trap - INT TERM EXIT
  echo
  echo "Stopping Prahari..."
  kill 0 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# A fixed secret keeps you signed in across backend restarts.
export PRAHARI_JWT_SECRET="${PRAHARI_JWT_SECRET:-local-dev-secret-local-dev-secret-01}"
export PRAHARI_HTTP_ADDR="127.0.0.1:$API_PORT"

echo "Starting the API on http://127.0.0.1:$API_PORT ..."
(cd "$ROOT/backend" && go run ./cmd/api 2>&1 | sed -u 's/^/[api] /') &

for _ in $(seq 1 120); do
  curl -sf "http://127.0.0.1:$API_PORT/healthz" >/dev/null 2>&1 && break
  sleep 1
done
if ! curl -sf "http://127.0.0.1:$API_PORT/healthz" >/dev/null 2>&1; then
  echo "The API did not start within two minutes; see the [api] lines above."
  exit 1
fi

echo
echo "API is up. Open http://localhost:5173 and sign in as meow / prahari-lead"
echo
(cd "$ROOT/frontend" && npm run dev 2>&1 | sed -u 's/^/[web] /') &
wait
