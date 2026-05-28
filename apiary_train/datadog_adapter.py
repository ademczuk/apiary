"""Adapter: Datadog malicious-software-packages-dataset to scraped-case.v1.

The Datadog corpus is the largest curated set of malicious npm packages
publicly available (about 17,600 npm entries). Each package is encrypted
with the password ``infected`` and laid out under
``samples/npm/<intent_class>/<package>/<version>/``.

``scripts/fetch_datadog_dataset.py`` walks the corpus, extracts the
encrypted ZIPs, and emits a ``manifest.jsonl`` whose rows describe each
extracted package.

This adapter reads that manifest and emits one ``scraped-case.v1`` record
per package, in the same shape produced by Andreas's GHSA scraper and
the OSSF OSV adapter. Downstream ``apiary_train.scraped_case_adapter``
already understands that shape, so the SFT training pipeline accepts
all three sources uniformly.

Intent classes seen in the corpus:

* ``malicious_intent`` - the package only exists to attack
  (typosquats, dependency-confusion bait, command-and-control droppers).
  Severity inference defaults to ``critical`` because the entire package
  is hostile by design.
* ``compromised_lib`` - a real library that was briefly hijacked.
  Severity inference defaults to ``critical`` for matching versions and
  ``high`` for unlisted ones.

CLI:

    python -m apiary_train.datadog_adapter \\
        --input data/raw/datadog-malicious/manifest.jsonl \\
        --output data/raw/datadog-as-scraped-case.jsonl
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("apiary.datadog_adapter")


_SEVERITY_BY_INTENT = {
    "malicious_intent_all_versions": "critical",
    "malicious_intent": "critical",
    "compromised_lib_listed": "critical",
    "compromised_lib": "high",
}


def _infer_severity(intent_label: str) -> str:
    return _SEVERITY_BY_INTENT.get(intent_label, "high")


def _summary_for(package: str, version: str, intent_label: str, captured: str) -> str:
    """Human-readable summary used as the GHSA-style advisory text."""
    if intent_label.startswith("malicious_intent"):
        return (
            f"Datadog malicious-packages dataset entry for npm package "
            f"`{package}` (version {version}). Captured {captured}. The package "
            f"was published with malicious intent (typosquatting, "
            f"dependency-confusion, command-and-control dropper, or similar)."
        )
    return (
        f"Datadog malicious-packages dataset entry for npm package "
        f"`{package}` (version {version}). Captured {captured}. This is a "
        f"compromised release of an otherwise legitimate library."
    )


def datadog_to_scraped_case(entry: dict) -> dict | None:
    """Convert one manifest.jsonl row to a scraped-case.v1 dict.

    Returns None if the entry is missing the basic identity fields.
    """
    package = entry.get("package")
    version = entry.get("version")
    if not package or not version:
        return None

    intent_label = entry.get("intent_label") or "malicious_intent"
    intent_class = entry.get("intent_class") or "malicious_intent"
    captured = entry.get("captured_date") or "unknown"
    severity = _infer_severity(intent_label)
    summary = _summary_for(package, version, intent_label, captured)

    case_id = f"datadog_{intent_class}_{package}@{version}"
    advisory_id = f"DATADOG-{intent_class.upper()}-{package}-{version}"

    # Datadog provenance survives in the npm.* escape hatch alongside
    # the on-disk path so downstream consumers can locate the extracted
    # tarball if they want to inspect it.
    npm_block = {
        "datadog_intent_class": intent_class,
        "datadog_intent_label": intent_label,
        "datadog_captured_date": captured,
        "extracted_to": entry.get("extracted_to"),
        "extracted_file_count": entry.get("extracted_file_count"),
        "source_zip": entry.get("source_zip"),
    }

    return {
        "schema_version": "modulewarden.scraped_case.v1",
        "case_id": case_id,
        "source": "datadog",
        "case_type": "incident_replay",
        "package": package,
        "advisory_ids": [advisory_id],
        "severity": severity,
        "summary": summary,
        "cwes": ["CWE-506"],
        "affected_range": f"=={version}",
        "first_patched_version": None,
        "candidate_versions": [
            {
                "role": "likely_affected",
                "version": version,
                "published_at": captured if captured != "unknown" else None,
            }
        ],
        "benign_neighbor_versions": [],
        "references": [
            "https://github.com/DataDog/malicious-software-packages-dataset",
        ],
        "source_code_location": entry.get("extracted_to"),
        "npm": npm_block,
        "osv_ids": [],
        "triage_status": "candidate",
        "scraped_at": datetime.now(timezone.utc).isoformat(),
    }


def _iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def convert(input_path: Path, output_path: Path) -> dict:
    """Stream manifest.jsonl into scraped-case.v1 JSONL. Returns stats."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    stats: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    intent_counts: Counter[str] = Counter()
    year_counts: Counter[str] = Counter()
    with output_path.open("w", encoding="utf-8") as out_fh:
        for entry in _iter_jsonl(input_path):
            stats["seen"] += 1
            scraped = datadog_to_scraped_case(entry)
            if scraped is None:
                stats["filtered_missing_identity"] += 1
                continue
            out_fh.write(json.dumps(scraped, ensure_ascii=False) + "\n")
            stats["written"] += 1
            severity_counts[scraped["severity"]] += 1
            intent_counts[(scraped.get("npm") or {}).get("datadog_intent_label", "unknown")] += 1
            captured = (scraped.get("npm") or {}).get("datadog_captured_date")
            if isinstance(captured, str) and len(captured) >= 4:
                year_counts[captured[:4]] += 1

    return {
        "seen": stats["seen"],
        "written": stats["written"],
        "filtered_missing_identity": stats["filtered_missing_identity"],
        "severity_distribution": dict(severity_counts),
        "intent_distribution": dict(intent_counts),
        "year_distribution": dict(sorted(year_counts.items())),
        "input": str(input_path),
        "output": str(output_path),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/raw/datadog-malicious/manifest.jsonl"),
        help="Manifest JSONL emitted by scripts/fetch_datadog_dataset.py.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/datadog-as-scraped-case.jsonl"),
        help="Destination scraped-case.v1 JSONL.",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.input.is_file():
        logger.error("manifest not found: %s", args.input)
        return 1

    stats = convert(args.input, args.output)
    logger.info(
        "wrote %d scraped-case records to %s (seen=%d, dropped=%d)",
        stats["written"],
        stats["output"],
        stats["seen"],
        stats["seen"] - stats["written"],
    )
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
