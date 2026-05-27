#!/usr/bin/env bash
# Smoke test for the Bumblebee -> apiary v2 proxy bridge.
#
# Boots a tiny stub of the v2 proxy via Python (no real npm, no real
# tarballs), pipes a fake Bumblebee NDJSON scan into the bridge, and
# asserts that postmark-mcp@1.0.16 is blocked. Returns 0 on success,
# non-zero on failure. Safe to run in CI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PYTHON="${PYTHON:-python}"

cd "${REPO_ROOT}"

echo "[smoke] starting stub proxy and running bridge"
"${PYTHON}" -m bumblebee_bridge.smoke "$@"
rc=$?

if [ "$rc" -eq 0 ]; then
  echo "[smoke] OK"
else
  echo "[smoke] FAIL (exit ${rc})"
fi
exit "${rc}"
