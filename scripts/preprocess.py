"""Build a HuggingFace Dataset from raw figshare + OSSF inputs.

Inputs:
    data/raw/figshare/*_unpacked/     # figshare NPMStudy unpacked archives
    data/raw/ossf-malpkg/osv/malicious/npm/  # OSSF OSV npm records

Output:
    data/processed/                   # HF Dataset arrow files
    data/processed/splits.json        # train/val/test stats

This is a SKELETON. The exact column schema depends on what the figshare
ZIP actually contains; we will not know until download_figshare.py has run.
The intent of this file is to give the model-training script a stable
interface: a HF Dataset with at least the columns

    package_name, version, source_kind, ecosystem, label, raw_text

where label is 0 (benign) or 1 (malicious) and raw_text is the install
script text, the package.json, or whatever blob CodeBERT will tokenize.

Usage:
    python scripts/preprocess.py [--in data/raw] [--out data/processed]

TODO:
    - Inspect a real figshare archive and lock down the input schema.
    - Decide on the unit of analysis (one release, one file, one chunk).
    - De-duplicate across figshare and OSSF (overlap is plausible).
    - Stratified split by ecosystem + label so eval is honest.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def iter_figshare_records(figshare_dir: Path):
    """Yield dicts from the unpacked figshare archive(s).

    TODO: implement once download_figshare.py has produced output.
    Until then, this yields nothing so downstream code can still run.
    """
    return
    yield  # unreachable; keeps the function a generator


def iter_ossf_records(ossf_dir: Path):
    """Yield dicts from the OSSF OSV npm tree.

    Returns one record per OSV file with the OSV id, package name,
    and a coarse "label=1, source_kind='ossf'" tag.
    """
    target = ossf_dir / "osv" / "malicious" / "npm"
    if not target.exists():
        return
    for path in target.rglob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        affected = data.get("affected", [])
        package_name = affected[0]["package"]["name"] if affected else None
        if not package_name:
            continue
        yield {
            "id": data.get("id"),
            "package_name": package_name,
            "version": None,
            "ecosystem": "npm",
            "source_kind": "ossf",
            "label": 1,
            "raw_text": data.get("details", "") or "",
        }


def stratified_split(records: list[dict], train: float, val: float):
    """Split records into train/val/test, stratified by (ecosystem, label).

    TODO: implement once the record stream is real. For now returns the
    whole input as train and empty val/test so the pipeline runs end-to-end.
    """
    return records, [], []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="in_dir", default="data/raw")
    parser.add_argument("--out", default="data/processed")
    parser.add_argument("--train", type=float, default=0.8)
    parser.add_argument("--val", type=float, default=0.1)
    args = parser.parse_args()

    in_dir = Path(args.in_dir)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    records.extend(iter_figshare_records(in_dir / "figshare"))
    records.extend(iter_ossf_records(in_dir / "ossf-malpkg"))
    print(f"Loaded {len(records)} records")

    train_rows, val_rows, test_rows = stratified_split(records, args.train, args.val)

    # TODO: save as HuggingFace Dataset (datasets.Dataset.from_list + save_to_disk).
    # For now drop JSONL so the downstream scripts see something on disk.
    for name, rows in [("train", train_rows), ("val", val_rows), ("test", test_rows)]:
        path = out_dir / f"{name}.jsonl"
        with path.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
        print(f"WROTE: {path} ({len(rows)} rows)")

    stats = {
        "train": len(train_rows),
        "val": len(val_rows),
        "test": len(test_rows),
        "total": len(records),
    }
    (out_dir / "splits.json").write_text(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
