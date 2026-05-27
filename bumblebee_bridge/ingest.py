"""Stream Bumblebee NDJSON records through the ModuleWarden gate.

Bumblebee schema (Apache 2.0, v0.1.1, github.com/perplexityai/bumblebee):
    Each line is a JSON record. We care about record_type == "package"
    with ecosystem == "npm". Fields used:
        - package_name (or normalized_name)
        - version
        - source_file (for the output table)
        - confidence

Usage:
    bumblebee scan --profile project --root ~/code | python -m bumblebee_bridge.ingest
    bumblebee scan --profile baseline | python -m bumblebee_bridge.ingest --gate http://localhost:8000

Output: a tab-separated table to stdout.
    package  version  score  decision  source_file

TODO:
    - Add a --json output mode for chaining.
    - Add --fail-on block so this can gate CI as a pre-install step.
    - Batch requests to the gate; one-at-a-time is fine for a demo but
      will be slow on a 5K-package baseline scan.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Iterator

import requests


def iter_npm_packages(lines: Iterator[str]) -> Iterator[dict]:
    """Yield (package_name, version, source_file) for npm package records."""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("record_type") != "package":
            continue
        if record.get("ecosystem") != "npm":
            continue
        name = record.get("normalized_name") or record.get("package_name")
        version = record.get("version")
        if not name or not version:
            continue
        yield {
            "package": name,
            "version": version,
            "source_file": record.get("source_file", ""),
        }


def score_one(gate_url: str, package: str, version: str, timeout: float = 10.0) -> dict:
    """POST to the gate; on failure return an open verdict so we never silently drop."""
    try:
        resp = requests.post(
            f"{gate_url.rstrip('/')}/score",
            json={"package": package, "version": version},
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:  # noqa: BLE001
        return {
            "package": package,
            "version": version,
            "score": -1.0,
            "decision": "ERROR",
            "evidence": [f"gate_error: {exc}"],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", default="http://localhost:8000")
    parser.add_argument("--limit", type=int, default=0, help="stop after N packages (0 = all)")
    parser.add_argument("--fail-on", choices=["block", "quarantine"], default=None,
                        help="exit non-zero if any package hits this decision or worse")
    args = parser.parse_args()

    # Header
    print("package\tversion\tscore\tdecision\tsource_file")

    seen_blocks = False
    seen_quarantines = False
    count = 0

    for pkg in iter_npm_packages(sys.stdin):
        verdict = score_one(args.gate, pkg["package"], pkg["version"])
        decision = verdict.get("decision", "?")
        score = verdict.get("score", -1.0)
        if decision == "block":
            seen_blocks = True
        elif decision == "quarantine":
            seen_quarantines = True
        print(f"{pkg['package']}\t{pkg['version']}\t{score:.3f}\t{decision}\t{pkg['source_file']}")
        count += 1
        if args.limit and count >= args.limit:
            break

    if args.fail_on == "block" and seen_blocks:
        return 2
    if args.fail_on == "quarantine" and (seen_blocks or seen_quarantines):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
