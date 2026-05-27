"""Build a HuggingFace Dataset from raw figshare archives.

Unzips the NPMStudy archive (streaming, lazy), walks the extracted tree to
find package directories, extracts the relevant text (package.json plus
scripts referenced in lifecycle hooks plus first 3 .js files by line count),
and emits both a JSONL manifest and an Arrow-backed HF Dataset with
stratified train/val/test splits.

Usage:
    python scripts/preprocess.py \
        --figshare-archive data/raw/figshare/NPMStudy.zip \
        --output data/processed/figshare/ \
        --seed 42
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("apiary.preprocess")

SEP = "<sep>"
MAX_FILE_BYTES = 64 * 1024  # cap any single file at 64 KB for tokenizer sanity
MAX_RECORD_BYTES = 256 * 1024  # cap the concatenated blob


def _setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _stream_unzip(archive: Path, extract_to: Path) -> Path:
    """Extract the figshare archive lazily; skip existing files.

    Returns the directory containing the extracted tree.
    """
    extract_to.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        raise FileNotFoundError(f"archive not found: {archive}")

    logger.info("opening archive: %s", archive)
    with zipfile.ZipFile(archive, mode="r") as zf:
        members = zf.namelist()
        logger.info("archive contains %d entries", len(members))
        for name in members:
            target = extract_to / name
            if target.exists() and target.is_file() and target.stat().st_size > 0:
                continue
            try:
                zf.extract(name, path=extract_to)
            except (OSError, zipfile.BadZipFile) as exc:
                logger.warning("skip %s: %s", name, exc)
    return extract_to


def _read_text_capped(path: Path, cap: int = MAX_FILE_BYTES) -> str:
    """Read a UTF-8 text file with replacement, capped at `cap` bytes."""
    try:
        with path.open("rb") as f:
            data = f.read(cap)
        return data.decode("utf-8", errors="replace")
    except OSError as exc:
        logger.debug("read failed for %s: %s", path, exc)
        return ""


def _find_package_dirs(root: Path) -> Iterator[Path]:
    """Yield directories that look like npm packages (contain package.json)."""
    for pkg_json in root.rglob("package.json"):
        # Skip nested node_modules - those are sub-dependencies, not the unit
        # of analysis. Walk only the outer package roots.
        parts = pkg_json.parts
        if "node_modules" in parts:
            continue
        yield pkg_json.parent


def _select_js_files(pkg_dir: Path, k: int = 3) -> list[Path]:
    """Pick the top-k .js files by line count from a package directory."""
    candidates: list[tuple[int, Path]] = []
    for js_path in pkg_dir.rglob("*.js"):
        if "node_modules" in js_path.parts:
            continue
        try:
            with js_path.open("rb") as f:
                # Cheap line-count: count newlines in a bounded read.
                chunk = f.read(MAX_FILE_BYTES)
            n_lines = chunk.count(b"\n")
        except OSError:
            continue
        candidates.append((n_lines, js_path))
    candidates.sort(key=lambda t: t[0], reverse=True)
    return [p for _, p in candidates[:k]]


def _extract_lifecycle_files(pkg_dir: Path, scripts: dict) -> list[Path]:
    """Resolve script paths referenced in package.json lifecycle hooks."""
    if not isinstance(scripts, dict):
        return []
    referenced: list[Path] = []
    lifecycle_keys = ("preinstall", "install", "postinstall", "prepublish", "prepare")
    for key in lifecycle_keys:
        cmd = scripts.get(key)
        if not isinstance(cmd, str):
            continue
        # Look for tokens that look like a relative path to a file
        for token in cmd.split():
            cleaned = token.strip(";|&'\"`")
            if cleaned.endswith((".js", ".cjs", ".mjs", ".sh")):
                candidate = pkg_dir / cleaned
                if candidate.exists() and candidate.is_file():
                    referenced.append(candidate)
    return referenced


def _label_for_package(pkg_dir: Path, archive_path: Path) -> int:
    """Infer label from path conventions in the figshare archive.

    The figshare NPMStudy archive separates malicious and benign packages
    under sibling directories; we look for the `malicious` keyword anywhere
    in the path. Fall back to 0 (benign) if neither word is present.
    """
    parts_lower = [p.lower() for p in pkg_dir.parts]
    if any("malicious" in p or "malign" in p or "mal_" in p for p in parts_lower):
        return 1
    if any(p == "benign" or "benign" in p for p in parts_lower):
        return 0
    # Heuristic fallback: archive filename hint
    if "malicious" in archive_path.name.lower():
        return 1
    return 0


def _record_for_package(pkg_dir: Path, archive_path: Path) -> dict | None:
    """Build a single record dict for one package directory."""
    pkg_json_path = pkg_dir / "package.json"
    pkg_json_text = _read_text_capped(pkg_json_path)
    if not pkg_json_text:
        return None
    try:
        pkg_meta = json.loads(pkg_json_text)
    except json.JSONDecodeError:
        pkg_meta = {}

    name = pkg_meta.get("name") or pkg_dir.name
    version = pkg_meta.get("version") or "0.0.0"
    scripts = pkg_meta.get("scripts") if isinstance(pkg_meta, dict) else {}

    blobs: list[str] = [pkg_json_text]

    for lifecycle_file in _extract_lifecycle_files(pkg_dir, scripts or {}):
        blobs.append(_read_text_capped(lifecycle_file))

    for js_file in _select_js_files(pkg_dir, k=3):
        blobs.append(_read_text_capped(js_file))

    text = SEP.join(b for b in blobs if b)
    if len(text) > MAX_RECORD_BYTES:
        text = text[:MAX_RECORD_BYTES]

    label = _label_for_package(pkg_dir, archive_path)

    return {
        "package_name": name,
        "version": version,
        "ecosystem": "npm",
        "source": "figshare",
        "label": int(label),
        "text": text,
        "package_json_scripts": scripts if isinstance(scripts, dict) else {},
    }


def _stratified_split(
    records: list[dict],
    train: float,
    val: float,
    seed: int,
) -> tuple[list[dict], list[dict], list[dict]]:
    """Stratified split by label. Test fraction = 1 - train - val."""
    rng = random.Random(seed)
    by_label: dict[int, list[dict]] = {}
    for r in records:
        by_label.setdefault(int(r["label"]), []).append(r)

    train_rows: list[dict] = []
    val_rows: list[dict] = []
    test_rows: list[dict] = []
    for _label, bucket in by_label.items():
        rng.shuffle(bucket)
        n = len(bucket)
        n_train = int(n * train)
        n_val = int(n * val)
        train_rows.extend(bucket[:n_train])
        val_rows.extend(bucket[n_train : n_train + n_val])
        test_rows.extend(bucket[n_train + n_val :])

    rng.shuffle(train_rows)
    rng.shuffle(val_rows)
    rng.shuffle(test_rows)
    return train_rows, val_rows, test_rows


def _save_hf_dataset(
    splits: dict[str, list[dict]],
    out_dir: Path,
) -> None:
    """Persist as a HuggingFace DatasetDict if `datasets` is importable."""
    try:
        from datasets import Dataset, DatasetDict
    except ImportError:
        logger.warning("`datasets` not installed; skipping Arrow output")
        return
    dsd = DatasetDict()
    for split_name, rows in splits.items():
        if not rows:
            # Empty splits are still useful for downstream code consistency
            dsd[split_name] = Dataset.from_list([])
            continue
        dsd[split_name] = Dataset.from_list(rows)
    dsd.save_to_disk(str(out_dir))
    logger.info("saved HuggingFace DatasetDict to %s", out_dir)


def _save_manifest(records: list[dict], path: Path) -> None:
    """Write manifest.jsonl with one record per line (excluding nested scripts)."""
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            # Don't bloat the manifest with the parsed scripts dict; it's
            # already embedded in `text` and consumed by extract_features.
            row = {k: v for k, v in r.items() if k != "package_json_scripts"}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    logger.info("wrote manifest: %s (%d records)", path, len(records))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--figshare-archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--extract-dir", type=Path, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--train", type=float, default=0.8)
    parser.add_argument("--val", type=float, default=0.1)
    parser.add_argument("--limit", type=int, default=0, help="stop after N packages (0 = all)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    archive: Path = args.figshare_archive
    out_dir: Path = args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    extract_dir = args.extract_dir or (out_dir.parent / "extracted" / archive.stem)
    _stream_unzip(archive, extract_dir)

    records: list[dict] = []
    for pkg_dir in _find_package_dirs(extract_dir):
        rec = _record_for_package(pkg_dir, archive)
        if rec is None:
            continue
        records.append(rec)
        if args.limit and len(records) >= args.limit:
            break

    logger.info("built %d records", len(records))
    if not records:
        logger.error("no records extracted; check archive contents")
        return 1

    label_dist = Counter(r["label"] for r in records)
    logger.info("label distribution: %s", dict(label_dist))

    train_rows, val_rows, test_rows = _stratified_split(
        records, args.train, args.val, args.seed
    )
    logger.info(
        "split sizes: train=%d val=%d test=%d",
        len(train_rows),
        len(val_rows),
        len(test_rows),
    )

    _save_manifest(records, out_dir / "manifest.jsonl")
    _save_manifest(train_rows, out_dir / "train.jsonl")
    _save_manifest(val_rows, out_dir / "val.jsonl")
    _save_manifest(test_rows, out_dir / "test.jsonl")

    _save_hf_dataset(
        {"train": train_rows, "val": val_rows, "test": test_rows},
        out_dir / "hf_dataset",
    )

    stats = {
        "total": len(records),
        "train": len(train_rows),
        "val": len(val_rows),
        "test": len(test_rows),
        "label_distribution": dict(label_dist),
        "seed": args.seed,
    }
    (out_dir / "splits.json").write_text(json.dumps(stats, indent=2))
    logger.info("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
