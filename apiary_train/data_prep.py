"""Convert figshare + synthetic npm corpora into SFT instruction format.

Each output JSONL record is a chat-style conversation that teaches the
target model the task: ingest an npm package payload, return a structured
JSON verdict matching ``apiary_auditors.criteria.default-criteria``.

Record schema (one per line):

    {
      "messages": [
        {"role": "system", "content": "<system prompt>"},
        {"role": "user",   "content": "<package contents + question>"},
        {"role": "assistant", "content": "<JSON verdict>"}
      ],
      "meta": {
        "package": "postmark-mcp@1.0.16",
        "label": "malicious",
        "source": "figshare" | "synthetic" | "benign"
      }
    }

The label-inference fix from the parallel agent (commit 37e9140) is the
preferred ground-truth source; this module imports that helper when
available and falls back to a path heuristic with a warning otherwise.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

logger = logging.getLogger("apiary.data_prep")

SYSTEM_PROMPT = (
    "You are an npm supply-chain security auditor. Given a package's "
    "contents, decide whether it is clean, suspicious, or malicious. "
    "Return one JSON object with fields: verdict (one of clean, "
    "suspicious, malicious), confidence (float 0..1), reasoning (one "
    "paragraph), findings (list of short strings). Reply with the JSON "
    "object only, no surrounding text."
)

USER_TEMPLATE = (
    "Package: {name}@{version}\n"
    "Source: {source}\n"
    "\n"
    "Files included:\n"
    "{file_list}\n"
    "\n"
    "{file_blob}\n"
    "\n"
    "Is this package safe to install? Output the JSON object."
)

# Conservative char-per-token estimate; lines up with the auditor's
# existing CHARS_PER_TOKEN constant.
CHARS_PER_TOKEN = 4

# File-priority list. We always include package.json first; lifecycle
# scripts, common entry points, then everything else in size order.
PREFERRED_SUFFIXES = (".js", ".cjs", ".mjs", ".ts", ".json")
MAX_FILES_PER_PKG = 6


@dataclass
class PackageRecord:
    """Normalized view of one labelled package."""

    name: str
    version: str
    label: str  # one of clean / suspicious / malicious
    source: str  # figshare / synthetic / benign
    files: list[tuple[str, str]]  # (relpath, contents)

    def as_messages(self, max_chars: int) -> list[dict[str, str]]:
        """Build the chat-message triple, truncated to ``max_chars``."""
        verdict = self.label
        confidence = 0.97 if verdict == "malicious" else 0.92
        if verdict == "suspicious":
            confidence = 0.65
        reasoning, findings = _synthesize_assistant_reasoning(self)
        assistant = json.dumps(
            {
                "verdict": verdict,
                "confidence": confidence,
                "reasoning": reasoning,
                "findings": findings,
            },
            ensure_ascii=False,
        )
        file_blob, file_list = _format_file_blob(self.files, max_chars)
        user = USER_TEMPLATE.format(
            name=self.name,
            version=self.version,
            source=self.source,
            file_list=file_list,
            file_blob=file_blob,
        )
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]


def _format_file_blob(files: Sequence[tuple[str, str]], max_chars: int) -> tuple[str, str]:
    """Concatenate selected files until we hit the char budget."""
    selected: list[tuple[str, str]] = []
    used = 0
    for relpath, body in files[:MAX_FILES_PER_PKG]:
        remaining = max_chars - used
        if remaining <= 200:
            break
        truncated = body[:remaining]
        selected.append((relpath, truncated))
        used += len(truncated)
    blob = "\n\n".join(f"// FILE: {p}\n{b}" for p, b in selected)
    listing = "\n".join(f"- {p}" for p, _ in selected)
    return blob, listing


def _synthesize_assistant_reasoning(record: PackageRecord) -> tuple[str, list[str]]:
    """Produce a short pseudo-reasoning string and a findings list.

    Used as the target assistant message when we don't have a real
    auditor response. For figshare malicious entries we list the
    lifecycle hooks present and a few generic IoC strings; for benign
    we say it looks consistent with a normal release.
    """
    findings: list[str] = []
    if record.label == "malicious":
        for relpath, body in record.files:
            if relpath == "package.json":
                if '"postinstall"' in body:
                    findings.append("postinstall lifecycle hook present")
                if '"preinstall"' in body:
                    findings.append("preinstall lifecycle hook present")
                if '"prepare"' in body:
                    findings.append("prepare lifecycle hook present")
            for needle in ("child_process", "execSync", "spawn", "fs.readFile", "process.env", "fetch(", "https.request"):
                if needle in body:
                    findings.append(f"reference to {needle}")
                    break
        if not findings:
            findings.append("classified malicious by source corpus")
        reasoning = (
            "Package matches known malicious patterns in the training "
            "corpus. Indicators above include suspicious lifecycle "
            "hooks and outbound calls or filesystem reads typical of "
            "credential exfiltration."
        )
    elif record.label == "suspicious":
        findings.append("requires manual review")
        reasoning = (
            "Package shows ambiguous signal: not a clean baseline match, "
            "not a confident malicious match. Recommend quarantine for "
            "human review."
        )
    else:
        findings.append("matches benign baseline pattern")
        reasoning = (
            "Package contents look consistent with a routine release. "
            "No suspicious lifecycle hooks, no outbound calls in install "
            "scripts, no obfuscation markers."
        )
    return reasoning, findings


# ---------------------------------------------------------------------------
# Figshare loading
# ---------------------------------------------------------------------------


def _load_label_helper() -> Any | None:
    """Try to import the label-inference helper from the parallel agent's fix.

    Returns the callable on success, None on failure.
    """
    candidates = [
        "scripts.preprocess",
        "scripts.build_dataset",
        "scripts.download_figshare",
    ]
    for module_name in candidates:
        try:
            mod = __import__(module_name, fromlist=["infer_label"])
        except Exception:
            continue
        fn = getattr(mod, "infer_label", None)
        if fn is not None:
            logger.info("using label helper from %s.infer_label", module_name)
            return fn
    logger.warning(
        "no infer_label helper found; falling back to path heuristic. "
        "label quality may be lower. See commit 37e9140."
    )
    return None


def _path_heuristic_label(member: str) -> str:
    """Last-resort label inference from path components."""
    lower = member.lower()
    if "malicious" in lower or "malware" in lower or "/mal/" in lower:
        return "malicious"
    if "benign" in lower or "clean" in lower or "/benign/" in lower:
        return "clean"
    return "suspicious"


def iter_figshare_packages(archive: Path, max_packages: int | None = None) -> Iterator[PackageRecord]:
    """Yield ``PackageRecord`` objects extracted from the figshare zip."""
    label_fn = _load_label_helper()
    archive = Path(archive)
    if not archive.exists():
        raise FileNotFoundError(f"figshare archive missing: {archive}")

    pkg_files: dict[str, dict[str, str]] = {}
    with zipfile.ZipFile(archive) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            parts = info.filename.split("/")
            if len(parts) < 3:
                continue
            pkg_id = "/".join(parts[:-1])
            try:
                body = zf.read(info).decode("utf-8", errors="replace")
            except Exception:
                continue
            pkg_files.setdefault(pkg_id, {})[parts[-1]] = body

    count = 0
    for pkg_id, files in pkg_files.items():
        if "package.json" not in files:
            continue
        try:
            pj = json.loads(files["package.json"])
        except json.JSONDecodeError:
            pj = {}
        name = str(pj.get("name") or pkg_id.split("/")[-1])
        version = str(pj.get("version") or "unknown")
        if label_fn is not None:
            try:
                label = label_fn(pkg_id, files)
            except Exception:
                label = _path_heuristic_label(pkg_id)
        else:
            label = _path_heuristic_label(pkg_id)
        file_list = _select_priority_files(files)
        yield PackageRecord(
            name=name,
            version=version,
            label=label,
            source="figshare",
            files=file_list,
        )
        count += 1
        if max_packages is not None and count >= max_packages:
            break


def _select_priority_files(files: dict[str, str]) -> list[tuple[str, str]]:
    """Order files so package.json is first, then JS/TS by size ascending."""
    ordered: list[tuple[str, str]] = []
    if "package.json" in files:
        ordered.append(("package.json", files["package.json"]))
    rest = [
        (name, body)
        for name, body in files.items()
        if name != "package.json"
        and Path(name).suffix.lower() in PREFERRED_SUFFIXES
    ]
    rest.sort(key=lambda kv: len(kv[1]))
    ordered.extend(rest[: MAX_FILES_PER_PKG - 1])
    return ordered


# ---------------------------------------------------------------------------
# Synthetic loading
# ---------------------------------------------------------------------------


def iter_synthetic_packages(synthetic_dir: Path, max_packages: int | None = None) -> Iterator[PackageRecord]:
    """Walk the synth output dir (manifest.jsonl + per-package folders)."""
    synthetic_dir = Path(synthetic_dir)
    manifest = synthetic_dir / "manifest.jsonl"
    if not manifest.exists():
        logger.warning("no synthetic manifest at %s; skipping", manifest)
        return
    count = 0
    with manifest.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            pkg_dir = synthetic_dir / rec.get("package_path", "")
            if not pkg_dir.exists():
                continue
            files: dict[str, str] = {}
            for path in sorted(pkg_dir.rglob("*")):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in PREFERRED_SUFFIXES:
                    continue
                try:
                    files[path.name] = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
            if "package.json" not in files:
                continue
            try:
                pj = json.loads(files["package.json"])
            except json.JSONDecodeError:
                pj = {}
            yield PackageRecord(
                name=str(pj.get("name") or rec.get("name") or pkg_dir.name),
                version=str(pj.get("version") or rec.get("version") or "0.0.0"),
                label=str(rec.get("label", "malicious")),
                source="synthetic",
                files=_select_priority_files(files),
            )
            count += 1
            if max_packages is not None and count >= max_packages:
                break


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------


def prepare_sft_dataset(
    records: Iterable[PackageRecord],
    out_path: Path,
    max_len_tokens: int = 8192,
    shuffle: bool = True,
    seed: int = 42,
    split_test_frac: float = 0.05,
) -> dict[str, Any]:
    """Materialize records into JSONL and return summary stats.

    Writes a train file at ``out_path`` and a sibling ``-test.jsonl``
    file holding ``split_test_frac`` of records for held-out eval.
    """
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    test_path = out_path.with_suffix(".test.jsonl") if out_path.suffix else out_path.parent / (out_path.name + ".test.jsonl")
    max_chars = max_len_tokens * CHARS_PER_TOKEN

    rng = random.Random(seed)
    records = list(records)
    if shuffle:
        rng.shuffle(records)

    n_test = max(1, int(len(records) * split_test_frac))
    test_records = records[:n_test]
    train_records = records[n_test:]

    stats: dict[str, Any] = {
        "train_count": 0,
        "test_count": 0,
        "by_label": {},
        "by_source": {},
        "token_lengths": [],
    }

    def _write(path: Path, recs: list[PackageRecord], bucket: str) -> None:
        with path.open("w", encoding="utf-8") as fh:
            for rec in recs:
                messages = rec.as_messages(max_chars=max_chars)
                line = {
                    "messages": messages,
                    "meta": {
                        "package": f"{rec.name}@{rec.version}",
                        "label": rec.label,
                        "source": rec.source,
                    },
                }
                fh.write(json.dumps(line, ensure_ascii=False) + "\n")
                stats[f"{bucket}_count"] += 1
                stats["by_label"][rec.label] = stats["by_label"].get(rec.label, 0) + 1
                stats["by_source"][rec.source] = stats["by_source"].get(rec.source, 0) + 1
                total_chars = sum(len(m["content"]) for m in messages)
                stats["token_lengths"].append(total_chars // CHARS_PER_TOKEN)

    _write(out_path, train_records, "train")
    _write(test_path, test_records, "test")

    lengths = stats["token_lengths"] or [0]
    lengths_sorted = sorted(lengths)
    stats["token_mean"] = sum(lengths) / len(lengths)
    stats["token_median"] = lengths_sorted[len(lengths_sorted) // 2]
    stats["token_max"] = max(lengths)
    stats["token_p95"] = lengths_sorted[int(len(lengths_sorted) * 0.95)]
    stats["target_context_window"] = max_len_tokens
    stats["context_utilization"] = stats["token_mean"] / max_len_tokens
    stats["train_path"] = str(out_path)
    stats["test_path"] = str(test_path)

    summary_path = out_path.with_suffix(".stats.json") if out_path.suffix else out_path.parent / (out_path.name + ".stats.json")
    summary_path.write_text(json.dumps({k: v for k, v in stats.items() if k != "token_lengths"}, indent=2), encoding="utf-8")
    logger.info("wrote stats summary to %s", summary_path)
    return stats


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Apiary SFT data preparation")
    parser.add_argument("--figshare-archive", type=Path, help="Path to figshare ZIP")
    parser.add_argument("--synthetic-dir", type=Path, help="Synthetic output dir with manifest.jsonl")
    parser.add_argument(
        "--andreas-data",
        type=Path,
        help="Path to Andreas's normalized SFT data (file or directory)",
    )
    parser.add_argument(
        "--ossf-data",
        type=Path,
        help=(
            "Path to OSSF malicious-packages scraped-case.v1 JSONL "
            "(emit with `python -m apiary_train.ossv_adapter`). Folded "
            "into the SFT corpus alongside figshare, synthetic, Andreas, "
            "and GHSA sources."
        ),
    )
    parser.add_argument("--output", required=True, type=Path, help="Output JSONL path")
    parser.add_argument("--max-len", type=int, default=8192, help="Target context window in tokens")
    parser.add_argument("--shuffle", action="store_true", default=True)
    parser.add_argument("--no-shuffle", dest="shuffle", action="store_false")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-figshare", type=int, default=None)
    parser.add_argument("--max-synthetic", type=int, default=None)
    parser.add_argument("--split-test-frac", type=float, default=0.05)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def _append_andreas_to_output(
    andreas_path: Path,
    train_out: Path,
    test_out: Path,
    split_test_frac: float,
    seed: int,
) -> dict[str, int]:
    """Normalize Andreas's data and append it to the train/test JSONL files.

    The adapter handles shape detection; we then split the resulting
    lines into train/test according to ``split_test_frac`` and append.
    """
    import random
    import tempfile

    from apiary_train.andreas_data_adapter import normalize_to_sft_format

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".jsonl",
        delete=False,
        encoding="utf-8",
    ) as tmp:
        tmp_path = Path(tmp.name)
    try:
        written, skipped = normalize_to_sft_format(andreas_path, tmp_path)
        lines = [
            line
            for line in tmp_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass

    rng = random.Random(seed)
    rng.shuffle(lines)
    n_test = max(1, int(len(lines) * split_test_frac)) if lines else 0
    test_lines = lines[:n_test]
    train_lines = lines[n_test:]
    if train_lines:
        with train_out.open("a", encoding="utf-8") as fh:
            for ln in train_lines:
                fh.write(ln + "\n")
    if test_lines:
        with test_out.open("a", encoding="utf-8") as fh:
            for ln in test_lines:
                fh.write(ln + "\n")
    logger.info(
        "andreas: wrote %d train + %d test (skipped %d)",
        len(train_lines),
        len(test_lines),
        skipped,
    )
    return {
        "andreas_train": len(train_lines),
        "andreas_test": len(test_lines),
        "andreas_skipped": skipped,
    }


def _append_ossf_to_output(
    ossf_path: Path,
    train_out: Path,
    test_out: Path,
    split_test_frac: float,
    seed: int,
) -> dict[str, int]:
    """Normalize OSSF scraped-case.v1 JSONL into SFT chat format and append.

    The OSSF fetch pipeline (``scripts/fetch_ossf_malicious_packages.py``
    then ``python -m apiary_train.ossv_adapter``) produces records in the
    same scraped-case.v1 shape as Andreas's GHSA scraper. We route each
    record through ``scraped_case_adapter.case_to_sft`` so OSSF cases
    train on the same chat-message format as GHSA cases.
    """
    import random

    from apiary_train.scraped_case_adapter import case_to_sft

    if not ossf_path.is_file():
        logger.warning("ossf data not found at %s; skipping", ossf_path)
        return {"ossf_train": 0, "ossf_test": 0, "ossf_skipped": 0}

    cases: list[dict] = []
    skipped = 0
    with ossf_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                cases.append(json.loads(line))
            except json.JSONDecodeError:
                skipped += 1

    rng = random.Random(seed)
    rng.shuffle(cases)
    n_test = max(1, int(len(cases) * split_test_frac)) if cases else 0
    test_cases = cases[:n_test]
    train_cases = cases[n_test:]

    def _emit(path: Path, bucket: list[dict], split: str) -> int:
        if not bucket:
            return 0
        written = 0
        with path.open("a", encoding="utf-8") as fh:
            for case in bucket:
                try:
                    sft = case_to_sft(case, split=split)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("skip ossf case %s: %s", case.get("case_id"), exc)
                    continue
                fh.write(json.dumps(sft, ensure_ascii=False) + "\n")
                written += 1
        return written

    n_train_written = _emit(train_out, train_cases, "train")
    n_test_written = _emit(test_out, test_cases, "test")
    logger.info(
        "ossf: wrote %d train + %d test (skipped %d malformed lines)",
        n_train_written,
        n_test_written,
        skipped,
    )
    return {
        "ossf_train": n_train_written,
        "ossf_test": n_test_written,
        "ossf_skipped": skipped,
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    records: list[PackageRecord] = []
    if args.figshare_archive:
        records.extend(iter_figshare_packages(args.figshare_archive, args.max_figshare))
    if args.synthetic_dir:
        records.extend(iter_synthetic_packages(args.synthetic_dir, args.max_synthetic))
    if not records and not args.andreas_data and not args.ossf_data:
        logger.error(
            "no records produced; pass --figshare-archive, --synthetic-dir, "
            "--andreas-data, or --ossf-data"
        )
        return 1
    if records:
        stats = prepare_sft_dataset(
            records,
            out_path=args.output,
            max_len_tokens=args.max_len,
            shuffle=args.shuffle,
            seed=args.seed,
            split_test_frac=args.split_test_frac,
        )
    else:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text("", encoding="utf-8")
        test_path = (
            out_path.with_suffix(".test.jsonl")
            if out_path.suffix
            else out_path.parent / (out_path.name + ".test.jsonl")
        )
        test_path.write_text("", encoding="utf-8")
        stats = {
            "train_count": 0,
            "test_count": 0,
            "by_label": {},
            "by_source": {},
            "train_path": str(out_path),
            "test_path": str(test_path),
        }
    if args.andreas_data:
        train_out = Path(stats["train_path"])
        test_out = Path(stats["test_path"])
        a_stats = _append_andreas_to_output(
            args.andreas_data,
            train_out,
            test_out,
            args.split_test_frac,
            args.seed,
        )
        stats.update(a_stats)
        stats["train_count"] = stats.get("train_count", 0) + a_stats["andreas_train"]
        stats["test_count"] = stats.get("test_count", 0) + a_stats["andreas_test"]
        stats["by_source"]["andreas"] = a_stats["andreas_train"] + a_stats["andreas_test"]
    if args.ossf_data:
        train_out = Path(stats["train_path"])
        test_out = Path(stats["test_path"])
        o_stats = _append_ossf_to_output(
            args.ossf_data,
            train_out,
            test_out,
            args.split_test_frac,
            args.seed,
        )
        stats.update(o_stats)
        stats["train_count"] = stats.get("train_count", 0) + o_stats["ossf_train"]
        stats["test_count"] = stats.get("test_count", 0) + o_stats["ossf_test"]
        stats["by_source"]["ossf"] = o_stats["ossf_train"] + o_stats["ossf_test"]
    print(json.dumps({k: v for k, v in stats.items() if k != "token_lengths"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
