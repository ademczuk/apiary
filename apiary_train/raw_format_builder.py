"""Raw classification-head training records from VersionPair output.

Andreas's "raw format" for the classification head: a (features, label)
pair where features are the package's source plus the unified diff
against the patched version, and the label is malicious (1) or benign
(0). Two records per VersionPair:

- unpatched: label = 1, the code that carried the GHSA-confirmed flaw
- patched: label = 0, the code that fixes it (control)

This is the supervised signal an XGBoost / CodeBERT-style classifier
trains on. Pairing same-package versions controls for stylistic
attribution noise: the classifier learns the difference, not the
maintainer.

Pipeline position::

    version_pair_extractor.py -> VersionPair
    raw_format_builder.py  <-- THIS  -> JSONL for classification head
    sft_lora.py / train_codebert.py
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Iterator

# Allow run-as-script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apiary_train.version_pair_extractor import (  # noqa: E402
    FileChange,
    VersionPair,
)

logger = logging.getLogger("apiary.raw_format_builder")

MAX_TEXT_CHARS = 32 * 1024  # 32 KiB per record text feature, classifier-friendly
DIFF_HEADER = "===== UNIFIED DIFF (unpatched -> patched) =====\n"
CODE_HEADER = "===== PACKAGE.JSON (slice) =====\n"
FILES_HEADER = "===== CHANGED FILE PATHS =====\n"


def _render_diff_block(file_changes: list[FileChange], cap: int) -> str:
    """Concatenate per-file unified diffs into a single text feature."""
    pieces: list[str] = []
    total = 0
    for fc in file_changes:
        header = f"--- a/{fc.path}\n+++ b/{fc.path}\n# change_kind={fc.change_kind}\n"
        body = fc.unified_diff
        block = header + body + "\n"
        if total + len(block) > cap:
            pieces.append(f"... [truncated at {cap} chars] ...\n")
            break
        pieces.append(block)
        total += len(block)
    return "".join(pieces)


def _render_package_json_slice(pair: VersionPair, role: str) -> str:
    """Render the relevant package.json slice for one role (before/after)."""
    side = "before" if role == "unpatched" else "after"
    slc = (pair.package_json_changes or {}).get(side) or {}
    return json.dumps(slc, ensure_ascii=False, indent=2)


def _render_changed_paths(pair: VersionPair) -> str:
    return "\n".join(
        f"[{fc.change_kind}] {fc.path} (+{fc.added_lines}/-{fc.removed_lines})"
        for fc in pair.file_changes
    )


def _render_text(pair: VersionPair, role: str) -> str:
    """Build the text feature for one role (unpatched / patched)."""
    parts = [
        f"PACKAGE: {pair.package}",
        f"VERSION: {pair.unpatched_version if role == 'unpatched' else pair.patched_version}",
        f"ROLE: {role}",
        f"SEVERITY: {pair.severity}",
        f"ADVISORIES: {', '.join(pair.advisory_ids) or 'none'}",
        "",
        CODE_HEADER,
        _render_package_json_slice(pair, role),
        "",
        FILES_HEADER,
        _render_changed_paths(pair),
        "",
        DIFF_HEADER,
        _render_diff_block(pair.file_changes, MAX_TEXT_CHARS // 2),
    ]
    rendered = "\n".join(parts)
    if len(rendered) > MAX_TEXT_CHARS:
        rendered = rendered[: MAX_TEXT_CHARS - 64] + "\n... [text truncated]\n"
    return rendered


def to_raw_classification_record(pair: VersionPair, label: int) -> dict[str, Any]:
    """Build one classification-head record.

    ``label`` is 1 (malicious / unpatched) or 0 (benign / patched). Use
    ``to_raw_pair`` if you want both records emitted in the conventional
    order.
    """
    if label not in (0, 1):
        raise ValueError(f"label must be 0 or 1, got {label}")
    role = "unpatched" if label == 1 else "patched"
    version = pair.unpatched_version if label == 1 else pair.patched_version
    advisory = (pair.advisory_ids or [""])[0]
    return {
        "text": _render_text(pair, role),
        "label": label,
        "package": pair.package,
        "version": version,
        "advisory_id": advisory,
        "role": role,
        "severity": pair.severity,
        "n_files_changed": len(pair.file_changes),
    }


def to_raw_pair(pair: VersionPair) -> list[dict[str, Any]]:
    """Emit both the malicious and the benign records for a VersionPair."""
    return [
        to_raw_classification_record(pair, 1),
        to_raw_classification_record(pair, 0),
    ]


def _iter_pairs(input_root: Path) -> Iterator[VersionPair]:
    """Walk a version-pairs output tree and yield reconstructed VersionPair."""
    for pair_json in input_root.rglob("pair.json"):
        try:
            data = json.loads(pair_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("bad pair.json skipped: %s (%s)", pair_json, exc)
            continue
        if data.get("extraction_method") != "tarball_diff":
            logger.debug("skipping non-diff pair: %s", pair_json)
            continue
        file_changes = [
            FileChange(**fc) for fc in (data.get("file_changes") or [])
        ]
        yield VersionPair(
            package=data["package"],
            unpatched_version=data["unpatched_version"],
            patched_version=data["patched_version"],
            advisory_ids=list(data.get("advisory_ids") or []),
            severity=data.get("severity") or "unknown",
            file_changes=file_changes,
            package_json_changes=data.get("package_json_changes") or {},
            extraction_method=data["extraction_method"],
            notes=list(data.get("notes") or []),
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version-pairs",
        type=Path,
        default=Path("data/raw/version-pairs/"),
        help="Root directory written by extract_version_pairs.py.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/sft/raw-classification.jsonl"),
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.version_pairs.is_dir():
        logger.error("version-pairs dir not found: %s", args.version_pairs)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    n_pairs = 0
    n_records = 0
    with args.output.open("w", encoding="utf-8") as fh:
        for pair in _iter_pairs(args.version_pairs):
            n_pairs += 1
            for record in to_raw_pair(pair):
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                n_records += 1
    logger.info(
        "wrote %d raw classification records (%d VersionPairs) to %s",
        n_records,
        n_pairs,
        args.output,
    )
    return 0


__all__ = [
    "to_raw_classification_record",
    "to_raw_pair",
]


if __name__ == "__main__":
    sys.exit(main())
