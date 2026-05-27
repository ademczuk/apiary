"""Extract hand-crafted features from preprocessed npm package records.

Reads a manifest.jsonl (output of preprocess.py) and produces a parquet
file with one row per package: numeric features for the gradient-booster
fallback model and as auxiliary signals for the deep model.

Usage:
    python scripts/extract_features.py \
        --manifest data/processed/v1/manifest.jsonl \
        --output data/processed/v1/features.parquet
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

logger = logging.getLogger("apiary.features")

SEP = "<sep>"

BINARY_EXTS = (".node", ".so", ".exe", ".dll", ".dylib", ".bin")

SUSPICIOUS_REQUIRES = {
    "child_process",
    "fs",
    "net",
    "http",
    "https",
    "dns",
    "tls",
    "vm",
    "os",
    "crypto",
}

DOTFILE_PATTERNS = (
    r"\.ssh",
    r"\.bashrc",
    r"\.bash_profile",
    r"\.zshrc",
    r"\.npmrc",
    r"\.aws",
    r"/etc/",
    r"\.gitconfig",
    r"\.netrc",
)

# Compiled regexes (module scope = compiled once)
RE_BASE64 = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
RE_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
RE_EVAL_CALLS = re.compile(r"\beval\s*\(")
RE_NEW_FUNCTION = re.compile(r"\bnew\s+Function\s*\(")
RE_CHILD_PROCESS = re.compile(
    r"\b(?:child_process|spawn|spawnSync|exec|execSync|fork)\b"
)
RE_REQUIRE_STRING = re.compile(r"require\(\s*[\"']([^\"']+)[\"']\s*\)")
RE_REQUIRE_DYNAMIC = re.compile(r"require\(\s*([A-Za-z_$][A-Za-z0-9_$\.]*)")
RE_NETWORK_IMPORT = re.compile(
    r"require\(\s*[\"'](?:http|https|net|tls|dgram|axios|node-fetch|got)[\"']\s*\)"
    r"|import\s+.*?from\s+[\"'](?:axios|node-fetch|got|undici)[\"']"
    r"|\bfetch\s*\("
)
RE_FS_WRITE = re.compile(
    r"\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\("
)
RE_DOTFILE = re.compile("|".join(DOTFILE_PATTERNS))
RE_OBFUSCATED_IDENT = re.compile(
    r"\b(?:_0x[0-9a-fA-F]+|\$[A-Z_][A-Z0-9_]*|[a-zA-Z]{1,2}\$\$\$)\b"
)


def _setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c)


def _parse_package_json_blob(text: str) -> dict:
    """The first SEP-delimited blob is the package.json contents."""
    if not text:
        return {}
    head = text.split(SEP, 1)[0]
    try:
        return json.loads(head)
    except json.JSONDecodeError:
        return {}


def _flatten_install_scripts(scripts: dict) -> str:
    if not isinstance(scripts, dict):
        return ""
    return "\n".join(
        str(scripts.get(k, ""))
        for k in ("preinstall", "install", "postinstall", "prepublish", "prepare")
        if k in scripts
    )


def _count_lifecycle_hooks(scripts: dict) -> int:
    if not isinstance(scripts, dict):
        return 0
    keys = {"preinstall", "install", "postinstall", "prepublish", "prepare", "publish"}
    return sum(1 for k in scripts if k in keys)


def _mean_identifier_length(text: str) -> float:
    idents = RE_IDENT.findall(text or "")
    if not idents:
        return 0.0
    return sum(len(i) for i in idents) / len(idents)


def _count_dynamic_require(text: str) -> int:
    """Match require(expr) where expr is NOT a quoted string."""
    if not text:
        return 0
    # Find all require(...) and subtract the string-arg ones
    all_calls = len(re.findall(r"require\s*\(", text))
    string_calls = len(RE_REQUIRE_STRING.findall(text))
    return max(0, all_calls - string_calls)


def _binary_file_signal(meta: dict) -> bool:
    """Look at package.json `files` field + `bin` field for binary hints."""
    fields = []
    if isinstance(meta.get("files"), list):
        fields.extend(meta["files"])
    if isinstance(meta.get("bin"), dict):
        fields.extend(meta["bin"].values())
    elif isinstance(meta.get("bin"), str):
        fields.append(meta["bin"])
    return any(isinstance(f, str) and f.lower().endswith(BINARY_EXTS) for f in fields)


def extract_row(record: dict) -> dict:
    """Build the per-package feature row."""
    text: str = record.get("text", "") or ""
    meta = _parse_package_json_blob(text)
    scripts = meta.get("scripts") if isinstance(meta, dict) else {}
    scripts = scripts if isinstance(scripts, dict) else {}

    install_body = _flatten_install_scripts(scripts)

    deps = meta.get("dependencies") if isinstance(meta, dict) else {}
    dev_deps = meta.get("devDependencies") if isinstance(meta, dict) else {}
    deps = deps if isinstance(deps, dict) else {}
    dev_deps = dev_deps if isinstance(dev_deps, dict) else {}

    # File-derived signals - text-only because we no longer hold the tree
    n_sep_segments = text.count(SEP) + (1 if text else 0)

    has_install = "install" in scripts
    has_post = "postinstall" in scripts
    has_pre = "preinstall" in scripts

    pkg_name = record.get("package_name") or meta.get("name") or ""
    row = {
        "package_name": pkg_name,
        "version": record.get("version") or meta.get("version") or "0.0.0",
        "ecosystem": record.get("ecosystem", "npm"),
        "source": record.get("source", "unknown"),
        "label": int(record.get("label", 0)),
        "split": record.get("split", "train"),
        "n_files": int(n_sep_segments),
        "total_size_bytes": len(text),
        "has_install_script": bool(has_install),
        "has_postinstall_script": bool(has_post),
        "has_preinstall_script": bool(has_pre),
        "install_script_length": len(install_body),
        "n_lifecycle_hooks": _count_lifecycle_hooks(scripts),
        "n_dependencies": len(deps),
        "n_dev_dependencies": len(dev_deps),
        "has_binary_files": _binary_file_signal(meta),
        "entropy_install_script": shannon_entropy(install_body),
        "n_eval_calls": len(RE_EVAL_CALLS.findall(text)),
        "n_function_constructor": len(RE_NEW_FUNCTION.findall(text)),
        "n_child_process_calls": len(RE_CHILD_PROCESS.findall(text)),
        "n_fs_writes_to_dotfiles": _count_dotfile_writes(text),
        "n_network_calls": len(RE_NETWORK_IMPORT.findall(text)),
        "n_base64_strings": len(RE_BASE64.findall(text)),
        "n_obfuscated_identifiers": len(RE_OBFUSCATED_IDENT.findall(text)),
        "n_dynamic_require": _count_dynamic_require(text),
        "mean_identifier_length": _mean_identifier_length(text),
        "package_name_length": len(pkg_name),
        "package_age_days": _meta_field_or_nan(meta, "_age_days"),
        "n_authors_in_history": _meta_field_or_nan(meta, "_n_authors"),
    }
    return row


def _count_dotfile_writes(text: str) -> int:
    """Count fs.write* calls near dotfile paths.

    Heuristic: find each fs.write* call and inspect a 200-char window after
    it for a dotfile pattern.
    """
    if not text:
        return 0
    count = 0
    for m in RE_FS_WRITE.finditer(text):
        window = text[m.end() : m.end() + 200]
        if RE_DOTFILE.search(window):
            count += 1
    return count


def _meta_field_or_nan(meta: dict, field: str) -> float:
    """Return float(field) if present, else NaN. Supports custom underscore-fields."""
    if not isinstance(meta, dict):
        return float("nan")
    val = meta.get(field)
    if isinstance(val, (int, float)):
        return float(val)
    return float("nan")


def _iter_manifest(path: Path) -> Iterable[dict]:
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _write_parquet(rows: list[dict], path: Path) -> None:
    """Write rows to parquet via pandas+pyarrow if available, else JSONL twin."""
    try:
        import pandas as pd
    except ImportError:
        logger.warning("pandas not available; writing JSONL twin instead")
        twin = path.with_suffix(".jsonl")
        with twin.open("w", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        logger.info("wrote %s (%d rows)", twin, len(rows))
        return

    df = pd.DataFrame(rows)
    try:
        df.to_parquet(path, index=False)
        logger.info("wrote %s (%d rows, %d columns)", path, len(df), len(df.columns))
    except (ImportError, ValueError) as exc:
        logger.warning("parquet write failed (%s); falling back to JSONL", exc)
        twin = path.with_suffix(".jsonl")
        df.to_json(twin, orient="records", lines=True)
        logger.info("wrote %s (%d rows)", twin, len(rows))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    manifest: Path = args.manifest
    out_path: Path = args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not manifest.exists():
        logger.error("manifest not found: %s", manifest)
        return 1

    rows: list[dict] = []
    for record in _iter_manifest(manifest):
        rows.append(extract_row(record))

    logger.info("extracted features for %d records", len(rows))
    if not rows:
        logger.warning("no records produced; check manifest content")
        return 1

    _write_parquet(rows, out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
