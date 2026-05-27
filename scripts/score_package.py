"""Score a single npm package@version and emit a JSON verdict.

Usage:
    python scripts/score_package.py --package event-stream --version 3.3.6
    python scripts/score_package.py --package left-pad --version 1.0.0 --model models/xgb-fallback.pkl

Output (one line of JSON to stdout):
    {
        "package": "event-stream",
        "version": "3.3.6",
        "score": 0.42,
        "decision": "quarantine",
        "evidence": ["new_install_script", "obfuscation_entropy_5.4"],
        "model": "xgb-fallback-v1"
    }

The decision is computed from modulewarden_gate/thresholds.yaml.

TODO:
    - Fetch the tarball from the npm registry if not cached locally.
    - Extract install scripts + index files; run extract_features over them.
    - Run the chosen model; if CodeBERT not available, fall back to xgb.
    - Map model outputs into the evidence strings the demo expects.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

THRESHOLDS_PATH = Path(__file__).resolve().parent.parent / "modulewarden_gate" / "thresholds.yaml"


def load_thresholds(path: Path = THRESHOLDS_PATH) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def decide(score: float, thresholds: dict) -> str:
    """Map a score in [0, 1] to allow / quarantine / block."""
    if score < thresholds["allow_below"]:
        return "allow"
    if score >= thresholds["block_at_or_above"]:
        return "block"
    return "quarantine"


def fetch_package_blob(package: str, version: str) -> str:
    """Download the npm tarball and return the relevant text blob.

    TODO: real implementation:
        import requests, tarfile, io
        url = f"https://registry.npmjs.org/{package}/-/{package}-{version}.tgz"
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        with tarfile.open(fileobj=io.BytesIO(resp.content)) as tf:
            # concatenate install scripts + index.js + main field target
            ...
    """
    return ""


def score(package: str, version: str, model_path: Path | None) -> dict:
    """Compute the verdict for one package@version.

    For now this returns a STUB score so the demo pipeline runs end-to-end
    before training finishes. A pinned set of known-bad packages return
    high scores; everything else returns a low one. Replace with real model
    inference once train_xgb_fallback.py and train_codebert.py produce
    artifacts.
    """
    known_bad = {
        "event-stream": ("3.3.6", 0.97, ["dependency_swap_flatmap_stream", "exfil_to_external_host"]),
        "eslint-scope": ("3.7.2", 0.93, ["compromised_maintainer_token", "credential_exfiltration"]),
        "ua-parser-js": ("0.7.29", 0.92, ["coin_miner_payload", "install_script_curl_pipe_sh"]),
        "rc": ("1.2.9", 0.88, ["typosquat_pattern", "obfuscated_blob"]),
        "coa": ("2.0.3", 0.86, ["typosquat_pattern", "post_install_dropper"]),
    }
    info = known_bad.get(package)
    if info and info[0] == version:
        return {
            "package": package,
            "version": version,
            "score": info[1],
            "evidence": info[2],
            "model": "stub-v0",
        }

    # TODO: real model inference here
    return {
        "package": package,
        "version": version,
        "score": 0.02,
        "evidence": [],
        "model": "stub-v0",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--model", default=None, help="path to a trained model artifact")
    parser.add_argument("--thresholds", default=str(THRESHOLDS_PATH))
    args = parser.parse_args()

    thresholds = load_thresholds(Path(args.thresholds))
    model_path = Path(args.model) if args.model else None

    verdict = score(args.package, args.version, model_path)
    verdict["decision"] = decide(verdict["score"], thresholds)
    print(json.dumps(verdict))
    return 0


if __name__ == "__main__":
    sys.exit(main())
