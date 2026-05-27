#!/usr/bin/env bash
# 60-second judges' demo for ModuleWarden gate.
#
# Pre-flight:
#   uv pip install -e .
#   uvicorn modulewarden_gate.gate:app --host 0.0.0.0 --port 4873 &
#
# Run:
#   bash demo/live_demo.sh

set -euo pipefail

GATE_URL="${GATE_URL:-http://localhost:4873}"
PACE="${PACE:-1.0}"

REPO_URL="https://github.com/apiary-project/apiary"

pause() { sleep "$(echo "$PACE * $1" | bc -l 2>/dev/null || echo "$1")"; }

# Pre-flight
if ! curl -sf "${GATE_URL}/healthz" > /dev/null; then
    echo "ERROR: gate is not reachable at ${GATE_URL}" >&2
    echo "Start it with: uvicorn modulewarden_gate.gate:app --host 0.0.0.0 --port 4873" >&2
    exit 1
fi

echo "=================================================================="
echo "  ModuleWarden gate live demo"
echo "  Gate: ${GATE_URL}"
echo "=================================================================="
echo
pause 1.0

# Step 0a: retroactive incident replay - the headline moment.
echo ""
echo "===== INCIDENT REPLAY: postmark-mcp@1.0.16 (Sep 2025 real-world malicious package) ====="
python demo/run_incident_replay.py --incident postmark-mcp-1.0.16 || true
pause 3.0
echo ""
echo "===== Same package, ONE VERSION EARLIER: postmark-mcp@1.0.12 (legitimate) ====="
python demo/run_incident_replay.py --incident postmark-mcp-1.0.12
pause 3.0

# Step 1: intro
echo "[1/5] Developers install npm packages every day."
echo "      A handful are malicious. ModuleWarden adds the verdict."
echo
pause 2.0

# Step 2: known-good package (lodash)
echo "[2/5] Scoring lodash@4.17.21 (known good)..."
GOOD_OUT="$(curl -sf -X POST "${GATE_URL}/score" \
    -H 'Content-Type: application/json' \
    -d '{"package": "lodash", "version": "4.17.21"}' || echo '{"error": "request failed"}')"
echo "      ${GOOD_OUT}"
echo
pause 2.0

# Step 3: known-bad package (postmark-mcp incident)
echo "[3/5] Scoring postmark-mcp@1.0.16 (known compromised)..."
BAD_OUT="$(curl -sf -X POST "${GATE_URL}/score" \
    -H 'Content-Type: application/json' \
    -d '{"package": "postmark-mcp", "version": "1.0.16"}' || echo '{"error": "request failed"}')"
echo "      ${BAD_OUT}"
echo
pause 2.0

# Step 4: pipe a Bumblebee-shaped scan through the bridge
echo "[4/5] Streaming a Bumblebee inventory through the bridge..."
SEED_FILE="${SEED_FILE:-demo/seed_packages.txt}"
if [[ ! -f "$SEED_FILE" ]]; then
    echo "ERROR: missing seed file: $SEED_FILE" >&2
    exit 1
fi

python - "$SEED_FILE" <<'PY' | python -m bumblebee_bridge.ingest --gate-url "${GATE_URL}"
import json, sys
seed = sys.argv[1]
with open(seed, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "@" not in line:
            continue
        name, _, version = line.partition("@")
        print(json.dumps({
            "record_type": "package",
            "ecosystem": "npm",
            "package_name": name,
            "normalized_name": name,
            "version": version,
            "source_file": f"node_modules/{name}/package.json",
            "confidence": "high",
        }))
PY
echo
pause 1.0

# Step 5: summary
echo "[5/5] That is the gate: score, decision, evidence per package."
echo "      Repo: ${REPO_URL}"
echo "=================================================================="
