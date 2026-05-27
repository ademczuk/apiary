#!/usr/bin/env bash
# Record the apiary demo as an asciinema .cast for use as a backup when the
# live stage demo fails. Records, plays back for operator verification, then
# (optionally) renders an SVG via asciinema-agg for slide-deck embedding and
# prints the asciinema.org upload command.
#
# Target runtime: 60-75 seconds. Each step has a deliberate sleep so the
# verdict text and Control Evidence Memo can be read on screen during the
# recording.
#
# Windows notes:
#   - asciinema does not run natively on Windows. Use WSL2 (Ubuntu) or git-bash
#     with a Linux-compatible asciinema build. Easiest path: WSL.
#   - From PowerShell, run: wsl bash demo/record_backup.sh
#   - The Python entry points (apiary-quarantine, run_incident_replay.py) must
#     resolve inside the same shell. Activate the venv before invoking.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"
RECORDINGS_DIR="${HERE}/recordings"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CAST_FILE="${RECORDINGS_DIR}/backup-demo-${TIMESTAMP}.cast"
SVG_FILE="${RECORDINGS_DIR}/backup-demo-${TIMESTAMP}.svg"

mkdir -p "${RECORDINGS_DIR}"

# ----------------------------------------------------------------------------
# Pre-flight: required tools
# ----------------------------------------------------------------------------

require() {
    local cmd="$1"
    local hint="$2"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "FAIL: '${cmd}' is required but not on PATH." >&2
        echo "  Install hint: ${hint}" >&2
        exit 1
    fi
}

require asciinema "macOS: brew install asciinema | Debian/Ubuntu: apt install asciinema | Windows: use WSL2"

ASCIINEMA_VERSION="$(asciinema --version 2>&1 | head -n1 || true)"
echo "Detected: ${ASCIINEMA_VERSION}"

HAS_AGG=0
if command -v agg >/dev/null 2>&1; then
    HAS_AGG=1
    echo "Detected: agg (will produce SVG render)"
else
    echo "Note: agg not installed; skipping SVG render."
    echo "  Install hint: cargo install --git https://github.com/asciinema/agg"
fi

cd "${REPO_ROOT}"

# Resolve a Python that has apiary installed.
if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    PYTHON="python"
elif [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
    PYTHON="${REPO_ROOT}/.venv/bin/python"
elif [[ -x "${REPO_ROOT}/.venv/Scripts/python.exe" ]]; then
    PYTHON="${REPO_ROOT}/.venv/Scripts/python.exe"
else
    PYTHON="${PYTHON:-python}"
fi
export PYTHON

# Sanity check: scripted demo paths exist.
for f in \
    "${HERE}/run_incident_replay.py" \
    "${HERE}/prestage_allowlist.py" \
; do
    if [[ ! -f "${f}" ]]; then
        echo "FAIL: required file not found: ${f}" >&2
        exit 1
    fi
done

# ----------------------------------------------------------------------------
# The script asciinema actually records.
# ----------------------------------------------------------------------------
#
# Written to a temp file so it survives the asciinema subshell hand-off. Each
# command is preceded by an `echo` banner and followed by a `sleep` so the
# viewer has time to read the output.

SCRIPT_FILE="$(mktemp --suffix=.sh)"
trap 'rm -f "${SCRIPT_FILE}"' EXIT

cat > "${SCRIPT_FILE}" <<'INNER_EOF'
#!/usr/bin/env bash
set -e
PS1='$ '

banner() {
    printf '\n\033[1;36m== %s ==\033[0m\n' "$1"
    sleep 1
}

banner "Step 1: validate the pre-staged allowlist"
apiary-quarantine validate
sleep 4

banner "Step 2: lodash@4.17.21 (clean baseline -> ALLOW)"
"${PYTHON}" demo/run_incident_replay.py --incident lodash-4.17.21
sleep 6

banner "Step 3: postmark-mcp@1.0.16 (Sept 2025 incident -> BLOCK)"
"${PYTHON}" demo/run_incident_replay.py --incident postmark-mcp-1.0.16
sleep 6

banner "Step 4: read the Control Evidence Memo we just produced"
ls -1t demo/outputs/postmark-mcp-1.0.16__*.md | head -n1 | xargs cat
sleep 8

banner "Step 5: postmark-mcp@1.0.12 (safe fallback -> ALLOW)"
"${PYTHON}" demo/run_incident_replay.py --incident postmark-mcp-1.0.12
sleep 6

banner "Demo complete. Five steps, three verdicts, one audit memo."
sleep 2
INNER_EOF

chmod +x "${SCRIPT_FILE}"

# ----------------------------------------------------------------------------
# Record
# ----------------------------------------------------------------------------

echo
echo "Recording to: ${CAST_FILE}"
echo "Target runtime: ~60-75 seconds."
echo

# --overwrite so re-recording from the same shell doesn't prompt.
# --title and --idle-time-limit make the cast cleaner for stage playback.
# We pass a small bootstrap that execs the inner script under the recorded
# shell so command echo + colors are preserved.
FORCE_COLOR=1 asciinema rec \
    --overwrite \
    --title "Apiary demo backup (${TIMESTAMP})" \
    --idle-time-limit 3 \
    --command "FORCE_COLOR=1 PYTHON=${PYTHON} bash ${SCRIPT_FILE}" \
    "${CAST_FILE}"

echo
echo "Recording finished. Wrote: ${CAST_FILE}"

# ----------------------------------------------------------------------------
# Playback for operator verification
# ----------------------------------------------------------------------------

echo
read -r -p "Play back the recording now to verify? [Y/n] " REPLY
REPLY="${REPLY:-Y}"
if [[ "${REPLY}" =~ ^[Yy] ]]; then
    asciinema play "${CAST_FILE}"
fi

# ----------------------------------------------------------------------------
# Optional SVG render
# ----------------------------------------------------------------------------

if [[ "${HAS_AGG}" -eq 1 ]]; then
    echo
    echo "Rendering SVG via agg..."
    agg --theme monokai --speed 1.0 "${CAST_FILE}" "${SVG_FILE}"
    echo "Wrote: ${SVG_FILE}"
fi

# ----------------------------------------------------------------------------
# Upload guidance (do NOT auto-upload; the operator may want to trim first)
# ----------------------------------------------------------------------------

cat <<EOF

==================================================================
Backup recording is ready.

  Cast file: ${CAST_FILE}
$([[ "${HAS_AGG}" -eq 1 ]] && echo "  SVG file : ${SVG_FILE}")

Next steps (manual):

  1. Upload to asciinema.org (creates an unlisted public URL):
       asciinema upload "${CAST_FILE}"
  2. Save the returned URL into demo/backup-urls.txt.
  3. Record a screen capture (OBS / Loom) of asciinema playing it,
     upload that to YouTube unlisted, save the URL alongside.
  4. Embed the SVG in the slide deck if you have one.

If the cast looks wrong (typos, missed steps, wrong colors), just
re-run this script. Old casts are kept under demo/recordings/.
==================================================================
EOF
