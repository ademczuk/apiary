#!/usr/bin/env bash
# Pre-stage the demo allowlist.
#
# Thin shell wrapper around demo/prestage_allowlist.py. The Python script does
# the real work (parsing seed_packages.txt, calling apiary_quarantine.add,
# validating). This wrapper exists so the runbook can say
# `bash demo/prestage_allowlist.sh` and have it work the same on the team's
# Windows + WSL/git-bash setup.
#
# Windows note: works under Git Bash, WSL, and MSYS2. From PowerShell, prefer:
#   python demo\prestage_allowlist.py
# directly.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"

cd "${REPO_ROOT}"

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
    PYTHON="python"
elif [[ -x "${REPO_ROOT}/.venv/bin/python" ]]; then
    PYTHON="${REPO_ROOT}/.venv/bin/python"
elif [[ -x "${REPO_ROOT}/.venv/Scripts/python.exe" ]]; then
    PYTHON="${REPO_ROOT}/.venv/Scripts/python.exe"
else
    PYTHON="${PYTHON:-python}"
fi

echo "Using interpreter: ${PYTHON}"
echo

exec "${PYTHON}" "${HERE}/prestage_allowlist.py" "$@"
