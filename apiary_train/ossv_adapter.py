"""Adapter: OSSF malicious-packages OSV records to scraped-case.v1.

The OSSF malicious-packages corpus emits one OSV JSON per advisory in
the schema documented at https://ossf.github.io/osv-schema/. We map
each record into the same ``modulewarden.scraped_case.v1`` shape that
Andreas's GHSA scraper produces, so the downstream pipeline
(``apiary_train.scraped_case_adapter`` then SFT training) consumes both
sources uniformly.

Input:  JSONL manifest from ``scripts/fetch_ossf_malicious_packages.py``
        (one summary line per record, with ``source_path`` pointing at
        the full OSV JSON on disk).
Output: JSONL of scraped-case.v1 records that ``scraped_case_adapter``
        already understands.

CLI:

    python -m apiary_train.ossv_adapter \\
        --input data/raw/ossf-malicious-packages/manifest.jsonl \\
        --output data/raw/ossf-as-scraped-case.jsonl
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

logger = logging.getLogger("apiary.ossv_adapter")

# CWE -> coarse severity bucket. OSSF records rarely carry severity
# scores, so we infer from CWE class. CWE-506 (Embedded Malicious
# Code) dominates the corpus and is unambiguously critical.
_CRITICAL_CWES = {"CWE-506", "CWE-94", "CWE-78", "CWE-829", "CWE-915"}
_HIGH_CWES = {"CWE-77", "CWE-79", "CWE-352", "CWE-918"}


def _infer_severity(cwes: list[str], summary: str | None) -> str:
    """Pick a severity bucket from CWE classification + summary keywords."""
    cwe_set = {c.upper() for c in cwes if c}
    if cwe_set & _CRITICAL_CWES:
        return "critical"
    if cwe_set & _HIGH_CWES:
        return "high"
    text = (summary or "").lower()
    if any(token in text for token in ("backdoor", "credential", "exfil", "ransomware", "wiper")):
        return "critical"
    if any(token in text for token in ("malicious code", "malware", "trojan")):
        return "critical"
    return "high"


def _collect_versions(affected: list[dict]) -> list[dict]:
    """Flatten OSV affected[].versions into candidate_version records."""
    rows: list[dict] = []
    for entry in affected:
        for version in entry.get("versions") or []:
            rows.append({
                "role": "likely_affected",
                "version": str(version),
                "published_at": None,
            })
    return rows


def _affected_range(affected: list[dict]) -> str | None:
    """Render a human-readable range from OSV affected[].ranges."""
    chunks: list[str] = []
    for entry in affected:
        for rng in entry.get("ranges") or []:
            rtype = rng.get("type", "?")
            events = rng.get("events") or []
            introduced = None
            fixed = None
            last_affected = None
            for event in events:
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
                if "last_affected" in event:
                    last_affected = event["last_affected"]
            parts: list[str] = []
            if introduced is not None:
                parts.append(f">={introduced}")
            if fixed is not None:
                parts.append(f"<{fixed}")
            elif last_affected is not None:
                parts.append(f"<={last_affected}")
            if parts:
                chunks.append(f"[{rtype}] " + " ".join(parts))
    return "; ".join(chunks) if chunks else None


def _first_patched(affected: list[dict]) -> str | None:
    for entry in affected:
        for rng in entry.get("ranges") or []:
            for event in rng.get("events") or []:
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)
    return None


def ossv_to_scraped_case(record: dict) -> dict | None:
    """Convert one OSV record to a scraped-case.v1 dict.

    Returns None if the record lacks an npm package or a usable id.
    """
    rid = record.get("id")
    affected = record.get("affected") or []
    if not isinstance(rid, str) or not rid or not affected:
        return None

    pkg_info = affected[0].get("package") or {}
    package = pkg_info.get("name")
    ecosystem = pkg_info.get("ecosystem")
    if not package or ecosystem != "npm":
        return None

    aliases = record.get("aliases") or []
    ghsa_ids = [a for a in aliases if isinstance(a, str) and a.startswith("GHSA-")]
    cve_ids = [a for a in aliases if isinstance(a, str) and a.startswith("CVE-")]
    cwes: list[str] = []
    for entry in affected:
        for cwe in (entry.get("database_specific") or {}).get("cwes") or []:
            cwe_id = cwe.get("cweId")
            if cwe_id:
                cwes.append(cwe_id)
    cwes = sorted(set(cwes))

    severity = _infer_severity(cwes, record.get("summary"))

    advisory_ids = [rid] + ghsa_ids + cve_ids
    references = [r.get("url") for r in (record.get("references") or []) if r.get("url")]

    # OSSF source provenance is interesting metadata; tuck the
    # malicious-packages-origins list under npm.* so it survives the
    # schema's additionalProperties=true escape hatch.
    origins = (record.get("database_specific") or {}).get("malicious-packages-origins") or []
    sources = sorted({o.get("source") for o in origins if o.get("source")})

    return {
        "schema_version": "modulewarden.scraped_case.v1",
        "case_id": f"ossf_{rid}_{package}",
        "source": "osv",
        "case_type": "incident_replay",
        "package": package,
        "advisory_ids": advisory_ids,
        "severity": severity,
        "summary": record.get("summary"),
        "cwes": cwes,
        "affected_range": _affected_range(affected),
        "first_patched_version": _first_patched(affected),
        "candidate_versions": _collect_versions(affected),
        "benign_neighbor_versions": [],
        "references": references,
        "source_code_location": None,
        "npm": {
            "ossf_origins": sources,
            "published": record.get("published"),
            "modified": record.get("modified"),
        },
        "osv_ids": [rid] + ghsa_ids,
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


def _resolve_source_path(manifest_entry: dict, manifest_dir: Path) -> Path | None:
    """Find the full OSV JSON referenced by a manifest summary row."""
    raw = manifest_entry.get("source_path")
    if raw:
        candidate = Path(raw)
        if candidate.is_file():
            return candidate
    # Fallback: the manifest sits next to records/<ossf_id>.json
    rid = manifest_entry.get("ossf_id")
    if rid:
        candidate = manifest_dir / "records" / f"{rid}.json"
        if candidate.is_file():
            return candidate
    return None


def convert(input_path: Path, output_path: Path) -> dict:
    """Convert every manifest entry. Returns stats."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_dir = input_path.parent

    stats = Counter()
    severity_counts: Counter[str] = Counter()
    year_counts: Counter[str] = Counter()
    with output_path.open("w", encoding="utf-8") as out_fh:
        for entry in _iter_jsonl(input_path):
            stats["seen"] += 1
            source_path = _resolve_source_path(entry, manifest_dir)
            if source_path is None:
                stats["missing_source"] += 1
                continue
            try:
                record = json.loads(source_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("unreadable record %s: %s", source_path, exc)
                stats["unreadable"] += 1
                continue
            scraped = ossv_to_scraped_case(record)
            if scraped is None:
                stats["filtered_non_npm_or_invalid"] += 1
                continue
            out_fh.write(json.dumps(scraped, ensure_ascii=False) + "\n")
            stats["written"] += 1
            severity_counts[scraped["severity"]] += 1
            published = (scraped.get("npm") or {}).get("published")
            if isinstance(published, str) and len(published) >= 4:
                year_counts[published[:4]] += 1
    summary = {
        "seen": stats["seen"],
        "written": stats["written"],
        "missing_source": stats["missing_source"],
        "unreadable": stats["unreadable"],
        "filtered_non_npm_or_invalid": stats["filtered_non_npm_or_invalid"],
        "severity_distribution": dict(severity_counts),
        "year_distribution": dict(sorted(year_counts.items())),
        "input": str(input_path),
        "output": str(output_path),
    }
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/raw/ossf-malicious-packages/manifest.jsonl"),
        help="Manifest JSONL from fetch_ossf_malicious_packages.py.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/ossf-as-scraped-case.jsonl"),
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
