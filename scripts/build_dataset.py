"""Merge benign, synthetic, and (optional) real-malicious sources into a HF Dataset.

Reads the three manifest.jsonl files, selects signal-dense files per package,
tokenizes via the microsoft/codebert-base tokenizer, performs a stratified
train/val/test split by (label, source), and writes the result via
`dataset.save_to_disk`.

Usage:
    python scripts/build_dataset.py \
        --benign data/raw/benign-packages/manifest.jsonl \
        --synthetic data/synthetic/v1/manifest.jsonl \
        --real-mal data/raw/figshare/manifest.jsonl \
        --output data/processed/v1/ \
        --train-frac 0.7 --val-frac 0.15 --test-frac 0.15 \
        --seed 42
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger("build_dataset")

MAX_FILES_PER_PKG = 6
MAX_BYTES_PER_FILE = 32 * 1024  # 32 KB is plenty for tokenizer truncation


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def read_manifest(path: Path) -> list[dict[str, Any]]:
    """Read a JSONL manifest, returning a list of dicts (or [] if missing)."""
    if not path.exists():
        logger.warning("Manifest does not exist: %s (treating as empty)", path)
        return []
    out: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("Bad manifest line in %s: %s", path, exc)
    return out


def select_signal_files(pkg_dir: Path) -> list[Path]:
    """Pick package.json + install hooks + top JS files (by line count)."""
    if not pkg_dir.is_dir():
        return []
    picked: list[Path] = []

    pj = pkg_dir / "package.json"
    if pj.exists():
        picked.append(pj)

    # Install hooks named explicitly.
    for hook_name in ("preinstall.js", "install.js", "postinstall.js"):
        cand = pkg_dir / hook_name
        if cand.exists():
            picked.append(cand)

    # Any .js file mentioned in package.json scripts.
    if pj.exists():
        try:
            data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
            scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
            for hook in ("preinstall", "install", "postinstall"):
                cmd = scripts.get(hook, "")
                if isinstance(cmd, str) and cmd:
                    # Heuristic: any token ending in .js is probably a file path.
                    for token in cmd.split():
                        token = token.strip("'\"")
                        if token.endswith(".js"):
                            cand = pkg_dir / token
                            if cand.exists() and cand not in picked:
                                picked.append(cand)
        except (json.JSONDecodeError, OSError):
            pass

    # Top JS files by line count.
    js_files: list[tuple[int, Path]] = []
    for jf in pkg_dir.rglob("*.js"):
        if "node_modules" in jf.parts:
            continue
        if jf in picked:
            continue
        try:
            text = jf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        js_files.append((text.count("\n"), jf))
    js_files.sort(key=lambda x: x[0], reverse=True)
    for _, jf in js_files[:3]:
        if jf not in picked:
            picked.append(jf)

    return picked[:MAX_FILES_PER_PKG]


def gather_text(pkg_dir: Path) -> str:
    """Concatenate signal-dense files with file separators."""
    parts: list[str] = []
    for f in select_signal_files(pkg_dir):
        try:
            data = f.read_bytes()[:MAX_BYTES_PER_FILE]
            text = data.decode("utf-8", errors="replace")
        except OSError:
            continue
        rel = f.relative_to(pkg_dir).as_posix()
        parts.append(f"// === {rel} ===\n{text}")
    return "\n\n".join(parts)


def assign_split(
    keys: Iterable[tuple[Any, ...]],
    train_frac: float,
    val_frac: float,
    test_frac: float,
    rng: random.Random,
) -> dict[tuple[Any, ...], str]:
    """Stratified split assignment per (label, source) group."""
    total = train_frac + val_frac + test_frac
    if abs(total - 1.0) > 1e-6:
        raise ValueError(f"split fractions must sum to 1.0, got {total}")

    groups: dict[Any, list[tuple[Any, ...]]] = defaultdict(list)
    for key in keys:
        # Stratify by (label, source) -> first two elements of key.
        stratum = (key[0], key[1])
        groups[stratum].append(key)

    assignment: dict[tuple[Any, ...], str] = {}
    for stratum, items in groups.items():
        items_copy = list(items)
        rng.shuffle(items_copy)
        n = len(items_copy)
        n_train = int(round(n * train_frac))
        n_val = int(round(n * val_frac))
        # Test gets the remainder so fractions always sum.
        train_items = items_copy[:n_train]
        val_items = items_copy[n_train:n_train + n_val]
        test_items = items_copy[n_train + n_val:]
        for it in train_items:
            assignment[it] = "train"
        for it in val_items:
            assignment[it] = "val"
        for it in test_items:
            assignment[it] = "test"
    return assignment


def build_examples(
    entries: list[dict[str, Any]],
    source_tag: str,
) -> list[dict[str, Any]]:
    """Turn manifest rows into per-package examples with raw_text and label."""
    out: list[dict[str, Any]] = []
    for row in entries:
        path = row.get("path")
        if not path:
            continue
        pkg_dir = Path(path)
        if not pkg_dir.exists():
            logger.debug("manifest path missing on disk: %s", pkg_dir)
            continue
        text = gather_text(pkg_dir)
        if not text.strip():
            continue
        out.append({
            "package_path": str(pkg_dir),
            "package_name": pkg_dir.name,
            "label": int(row.get("label", 0)),
            "source": source_tag,
            "pattern_id": row.get("pattern_id"),
            "raw_text": text,
        })
    return out


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI args."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--benign", required=True, type=Path)
    p.add_argument("--synthetic", required=True, type=Path)
    p.add_argument("--real-mal", type=Path, default=None,
                   help="optional manifest of real-malicious packages")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--train-frac", type=float, default=0.7)
    p.add_argument("--val-frac", type=float, default=0.15)
    p.add_argument("--test-frac", type=float, default=0.15)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--tokenizer", default="microsoft/codebert-base")
    p.add_argument("--max-length", type=int, default=512)
    p.add_argument("--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    setup_logging(args.verbose)

    # Import heavy deps lazily so --help is fast.
    try:
        from datasets import Dataset, DatasetDict  # type: ignore
        from transformers import AutoTokenizer  # type: ignore
    except ImportError as exc:
        logger.error("Missing dependency: %s. Install transformers + datasets.", exc)
        return 2

    benign_rows = read_manifest(args.benign)
    synth_rows = read_manifest(args.synthetic)
    real_rows = read_manifest(args.real_mal) if args.real_mal else []

    logger.info(
        "Loaded manifests: benign=%d synthetic=%d real=%d",
        len(benign_rows), len(synth_rows), len(real_rows),
    )

    benign_ex = build_examples(benign_rows, "benign")
    synth_ex = build_examples(synth_rows, "synthetic")
    real_ex = build_examples(real_rows, "real_mal")

    # Synthetic manifest already contains benign rows with label=0; if that
    # is the case, drop dups so we don't double-count.
    if synth_ex:
        seen_paths = {ex["package_path"] for ex in benign_ex}
        synth_ex = [
            ex for ex in synth_ex
            if not (ex["label"] == 0 and ex["package_path"] in seen_paths)
        ]

    all_examples = benign_ex + synth_ex + real_ex
    logger.info("Total examples after dedup: %d", len(all_examples))
    if not all_examples:
        logger.error("No examples assembled; aborting.")
        return 1

    rng = random.Random(args.seed)
    keys = [
        (ex["label"], ex["source"], ex["package_path"])
        for ex in all_examples
    ]
    split = assign_split(
        keys=keys,
        train_frac=args.train_frac,
        val_frac=args.val_frac,
        test_frac=args.test_frac,
        rng=rng,
    )

    for ex, key in zip(all_examples, keys, strict=True):
        ex["split"] = split[key]

    # Tokenize.
    logger.info("Loading tokenizer: %s", args.tokenizer)
    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer)

    def _tok_batch(batch: dict[str, list[Any]]) -> dict[str, list[Any]]:
        enc = tokenizer(
            batch["raw_text"],
            truncation=True,
            max_length=args.max_length,
            padding=False,
        )
        return enc

    split_examples: dict[str, list[dict[str, Any]]] = {
        "train": [ex for ex in all_examples if ex["split"] == "train"],
        "val": [ex for ex in all_examples if ex["split"] == "val"],
        "test": [ex for ex in all_examples if ex["split"] == "test"],
    }

    ds_dict: dict[str, Any] = {}
    for split_name, items in split_examples.items():
        if not items:
            logger.warning("Split %s is empty; skipping", split_name)
            continue
        ds = Dataset.from_list(items)
        ds = ds.map(_tok_batch, batched=True, batch_size=64,
                    desc=f"tokenize/{split_name}")
        ds_dict[split_name] = ds

    if not ds_dict:
        logger.error("All splits empty; aborting.")
        return 1

    dataset = DatasetDict(ds_dict)
    args.output.mkdir(parents=True, exist_ok=True)
    dataset.save_to_disk(str(args.output))
    logger.info("Saved DatasetDict to %s", args.output)

    # Stats.
    stats: dict[str, Any] = {"by_split": {}}
    for split_name, ds in dataset.items():
        by_label = Counter(ds["label"])
        by_source = Counter(ds["source"])
        stats["by_split"][split_name] = {
            "count": len(ds),
            "by_label": dict(by_label),
            "by_source": dict(by_source),
        }
    stats_path = args.output / "stats.json"
    stats_path.write_text(json.dumps(stats, indent=2, sort_keys=True), encoding="utf-8")
    logger.info("Wrote stats to %s", stats_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
