#!/usr/bin/env bash
# 60-second judges' demo.
#
# Plays a fake Bumblebee scan from demo/seed_packages.txt through the gate
# and renders the verdict table. Designed to fit on one screen with no
# scrolling.
#
# Pre-flight:
#   uv pip install -e .
#   uvicorn modulewarden_gate.gate:app --port 8000 &
#   curl -sf http://localhost:8000/healthz
#
# Run:
#   bash demo/live_demo.sh

set -euo pipefail

GATE_URL="${GATE_URL:-http://localhost:8000}"
SEED_FILE="${SEED_FILE:-demo/seed_packages.txt}"

if ! curl -sf "${GATE_URL}/healthz" > /dev/null; then
    echo "Gate not reachable at ${GATE_URL}. Start it with:" >&2
    echo "    uvicorn modulewarden_gate.gate:app --port 8000" >&2
    exit 1
fi

if [[ ! -f "$SEED_FILE" ]]; then
    echo "Missing seed file: $SEED_FILE" >&2
    exit 1
fi

echo "=================================================================="
echo "  ModuleWarden gate live demo"
echo "  Gate: ${GATE_URL}"
echo "  Seed: ${SEED_FILE} ($(wc -l < "$SEED_FILE") packages)"
echo "=================================================================="
echo

# Render the seed list as Bumblebee NDJSON and pipe through the bridge
python - "$SEED_FILE" <<'PY' | python -m bumblebee_bridge.ingest --gate "${GATE_URL}"
import json, sys
seed = sys.argv[1]
with open(seed) as f:
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
echo "Done. Blocks and quarantines are the model output; allows are the controls."
