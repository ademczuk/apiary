"""Extract hand-crafted features from npm package contents.

These feed the gradient-booster fallback model (xgboost). The CodeBERT
model gets the raw text; this script makes the cheap, fast, interpretable
signals.

Feature families:
    AST: number of nodes, max depth, presence of eval/Function/setTimeout,
         requires of suspicious modules (child_process, fs, net, http, dns).
    install_script: any of preinstall/install/postinstall set, length of
                    the script body, network calls in script, base64 blobs.
    entropy: Shannon entropy of identifiers, max string entropy, average
             string entropy. High entropy is a tell for obfuscated payloads.
    package_meta: typo-distance to a top-1000 package, age in days, author
                  email reuse across many packages, version count.

Output: parquet file with one row per package@version.

Usage:
    python scripts/extract_features.py --in data/processed --out data/interim/features.parquet

TODO:
    - Plug in real AST parser (esprima for JS, or tree-sitter-javascript).
    - Implement top-1000 typo-distance with a precomputed BK-tree.
    - Make the entropy floor configurable; 4.5+ is "weird", 5.5+ is "blob".
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

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
}

SUSPICIOUS_GLOBALS = {"eval", "Function", "setTimeout", "setInterval"}

BASE64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
STRING_RE = re.compile(r"\"([^\"\\]|\\.)*\"|\'([^\'\\]|\\.)*\'")


def shannon_entropy(text: str) -> float:
    """Compute Shannon entropy of a string (bits per char)."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def install_script_features(scripts: dict) -> dict:
    """Pull features from package.json scripts block.

    scripts is the parsed JSON object; may be missing or empty.
    """
    if not isinstance(scripts, dict):
        scripts = {}
    install_keys = ("preinstall", "install", "postinstall")
    body = " ".join(str(scripts.get(k, "")) for k in install_keys)
    return {
        "has_install_script": int(any(k in scripts for k in install_keys)),
        "install_script_len": len(body),
        "install_script_entropy": shannon_entropy(body),
        "install_script_has_curl": int("curl " in body or "wget " in body),
        "install_script_has_pipe_sh": int("| sh" in body or "| bash" in body),
    }


def text_features(text: str) -> dict:
    """Cheap text-only features over the raw blob (install script, JS, etc.)."""
    requires = set(re.findall(r"require\([\"\']([^\"\']+)[\"\']\)", text or ""))
    globals_used = set(re.findall(r"\b(eval|Function|setTimeout|setInterval)\b", text or ""))
    strings = [m.group(0) for m in STRING_RE.finditer(text or "")]
    str_entropies = [shannon_entropy(s) for s in strings] or [0.0]
    return {
        "n_chars": len(text or ""),
        "n_lines": (text or "").count("\n") + 1 if text else 0,
        "suspicious_requires": len(requires & SUSPICIOUS_REQUIRES),
        "suspicious_globals": len(globals_used & SUSPICIOUS_GLOBALS),
        "max_string_entropy": max(str_entropies),
        "mean_string_entropy": sum(str_entropies) / len(str_entropies),
        "n_base64_blobs": len(BASE64_RE.findall(text or "")),
    }


def ast_features(text: str) -> dict:
    """Parse with esprima and extract structural features.

    TODO: handle parse errors gracefully (malicious code often is malformed
    or uses non-standard syntax). Return zeros + flag on failure.
    """
    # Stub for now; real implementation uses esprima.parseModule and walks
    # the tree counting node types, max depth, etc.
    return {
        "ast_n_nodes": 0,
        "ast_max_depth": 0,
        "ast_parse_failed": 1,
    }


def extract_row(record: dict) -> dict:
    """Turn one preprocessed record into a feature row."""
    text = record.get("raw_text", "") or ""
    scripts = record.get("package_json_scripts", {})
    row = {
        "package_name": record.get("package_name"),
        "version": record.get("version"),
        "ecosystem": record.get("ecosystem"),
        "label": record.get("label"),
    }
    row.update(install_script_features(scripts))
    row.update(text_features(text))
    row.update(ast_features(text))
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="in_dir", default="data/processed")
    parser.add_argument("--out", default="data/interim/features.parquet")
    args = parser.parse_args()

    in_dir = Path(args.in_dir)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rows: list[dict] = []
    for split in ("train", "val", "test"):
        path = in_dir / f"{split}.jsonl"
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as f:
            for line in f:
                record = json.loads(line)
                row = extract_row(record)
                row["split"] = split
                rows.append(row)

    print(f"Extracted features for {len(rows)} records")

    # TODO: write parquet via pyarrow. For now emit JSONL so this is runnable
    # without the binary dependency loaded.
    out_jsonl = out_path.with_suffix(".jsonl")
    with out_jsonl.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"WROTE: {out_jsonl}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
