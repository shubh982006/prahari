#!/usr/bin/env sh
# The dependency rule (design §3.1): the pure engine imports only domain and
# the standard library — never app, adapters or httpapi.
set -eu
cd "$(dirname "$0")/.."
bad=$(go list -deps ./internal/core/... | grep -E '^prahari/internal/(adapters|app|httpapi|config)(/|$)' || true)
if [ -n "$bad" ]; then
  echo "core imports outward — dependency rule violated:"
  echo "$bad"
  exit 1
fi
echo "dependency rule ok: internal/core imports only core, domain and stdlib"
