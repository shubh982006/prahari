#!/usr/bin/env bash
# Rule M1 (design §4.4): every migration lands in both dialect directories.
# The two directories must hold exactly the same file names.
set -eu
cd "$(dirname "$0")/../migrations"
pg=$(ls postgres | sort)
lite=$(ls sqlite | sort)
if [ "$pg" != "$lite" ]; then
  echo "migration parity violated (postgres vs sqlite):"
  diff <(echo "$pg") <(echo "$lite") || true
  exit 1
fi
echo "migration parity ok: $(echo "$pg" | wc -l | tr -d ' ') files in each dialect"
