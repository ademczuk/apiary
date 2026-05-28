"""CLI: extract version pairs for every scraped-case.v1 record.

Walks ``data/raw/scraped-ghsa/scraped-cases.jsonl`` and produces one
``pair.json`` plus a per-file diff directory under
``data/raw/version-pairs/{advisory_id}/{package_safe}/``. A
``manifest.jsonl`` line is appended for every processed case (success or
skip) so the next stage (raw / agentic format builders) has a single
catalog to consume.

Usage::

    python scripts/extract_version_pairs.py \\
        --scraped-cases data/raw/scraped-ghsa/scraped-cases.jsonl \\
        --output data/raw/version-pairs/ \\
        --concurrency 6 \\
        --max-cases 200 \\
        --skip-existing

Idempotent: a case is skipped on rerun if its ``pair.json`` already
exists under the expected output path.

npm registry rate limits:
    Public registry advertises ~50 req/sec per IP. Default concurrency 6
    keeps us well under that even on bursty extractions. The extractor
    backs off on HTTP 429.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

import httpx

# Make the script runnable both as ``python scripts/extract_version_pairs.py``
# from the repo root and via ``python -m scripts.extract_version_pairs``.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apiary_train.version_pair_extractor import (  # noqa: E402
    DEFAULT_REGISTRY,
    MAX_TARBALL_BYTES,
    VersionPair,
    extract_one,
)

logger = logging.getLogger("apiary.extract_version_pairs")

DEFAULT_TIMEOUT = 120.0
SAFE_PATH_RE = re.compile(r"[^A-Za-z0-9._@-]")


def _safe_path_token(s: str) -> str:
    """Make a filesystem-safe token out of a free-form string."""
    return SAFE_PATH_RE.sub("_", s).strip("_") or "_"


def _output_dir_for(
    output_root: Path, advisory_id: str, package: str
) -> Path:
    return output_root / _safe_path_token(advisory_id) / _safe_path_token(package)


def _iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("bad JSONL line skipped: %s", exc)


def _write_pair(out_dir: Path, pair: VersionPair) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    pair_json = out_dir / "pair.json"
    pair_json.write_text(
        json.dumps(pair.to_json_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    diffs_dir = out_dir / "diffs"
    diffs_dir.mkdir(exist_ok=True)
    for fc in pair.file_changes:
        safe_name = _safe_path_token(fc.path)[:200]
        ext = ".added.diff" if fc.change_kind == "added" else (
            ".removed.diff" if fc.change_kind == "removed" else ".diff"
        )
        out_path = diffs_dir / f"{safe_name}{ext}"
        out_path.write_text(fc.unified_diff, encoding="utf-8")


def _manifest_row(case: dict[str, Any], pair: VersionPair, out_dir: Path) -> dict[str, Any]:
    n_added = sum(1 for fc in pair.file_changes if fc.change_kind == "added")
    n_removed = sum(1 for fc in pair.file_changes if fc.change_kind == "removed")
    n_modified = sum(1 for fc in pair.file_changes if fc.change_kind == "modified")
    return {
        "case_id": case.get("case_id"),
        "package": pair.package,
        "advisory_id": (pair.advisory_ids[:1] or [""])[0],
        "severity": pair.severity,
        "unpatched_version": pair.unpatched_version,
        "patched_version": pair.patched_version,
        "extraction_method": pair.extraction_method,
        "n_files_changed": len(pair.file_changes),
        "n_added": n_added,
        "n_removed": n_removed,
        "n_modified": n_modified,
        "output_dir": str(out_dir),
        "notes": pair.notes,
    }


async def _process_one(
    case: dict[str, Any],
    output_root: Path,
    client: httpx.AsyncClient,
    work_dir: Path,
    registry: str,
    max_tarball_bytes: int,
    skip_existing: bool,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any] | None:
    advisory_id = (case.get("advisory_ids") or [None])[0] or "unknown_advisory"
    package = case.get("package") or "unknown_package"
    out_dir = _output_dir_for(output_root, advisory_id, package)
    pair_json = out_dir / "pair.json"
    if skip_existing and pair_json.is_file():
        logger.debug("skip existing %s", pair_json)
        try:
            cached = json.loads(pair_json.read_text(encoding="utf-8"))
            return {
                "case_id": case.get("case_id"),
                "package": cached.get("package"),
                "advisory_id": (cached.get("advisory_ids") or [""])[:1][0] if cached.get("advisory_ids") else "",
                "severity": cached.get("severity"),
                "unpatched_version": cached.get("unpatched_version"),
                "patched_version": cached.get("patched_version"),
                "extraction_method": cached.get("extraction_method"),
                "n_files_changed": len(cached.get("file_changes") or []),
                "n_added": sum(1 for fc in (cached.get("file_changes") or []) if fc.get("change_kind") == "added"),
                "n_removed": sum(1 for fc in (cached.get("file_changes") or []) if fc.get("change_kind") == "removed"),
                "n_modified": sum(1 for fc in (cached.get("file_changes") or []) if fc.get("change_kind") == "modified"),
                "output_dir": str(out_dir),
                "notes": cached.get("notes") or [],
                "cached": True,
            }
        except (OSError, json.JSONDecodeError):
            logger.warning("cached pair.json unreadable, reprocessing: %s", pair_json)

    async with semaphore:
        t0 = time.monotonic()
        try:
            pair = await extract_one(
                case, client, work_dir, registry, max_tarball_bytes
            )
        except Exception as exc:  # noqa: BLE001 - never let one case kill the run
            logger.exception("extract failed for %s: %s", case.get("case_id"), exc)
            return {
                "case_id": case.get("case_id"),
                "package": package,
                "advisory_id": advisory_id,
                "severity": case.get("severity") or "unknown",
                "unpatched_version": "",
                "patched_version": "",
                "extraction_method": "failed_unhandled_exception",
                "n_files_changed": 0,
                "n_added": 0,
                "n_removed": 0,
                "n_modified": 0,
                "output_dir": str(out_dir),
                "notes": [f"unhandled exception: {exc!r}"],
            }
        elapsed = time.monotonic() - t0

    if pair.extraction_method == "tarball_diff":
        _write_pair(out_dir, pair)
    else:
        # Always persist the failure / skip record so reruns honor
        # --skip-existing and the manifest stays in sync.
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "pair.json").write_text(
            json.dumps(pair.to_json_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    logger.info(
        "[%s] %s %s->%s files=%d method=%s (%.1fs)",
        pair.severity,
        pair.package,
        pair.unpatched_version or "?",
        pair.patched_version or "?",
        len(pair.file_changes),
        pair.extraction_method,
        elapsed,
    )
    return _manifest_row(case, pair, out_dir)


async def _run(
    cases: list[dict[str, Any]],
    output_root: Path,
    concurrency: int,
    registry: str,
    max_tarball_bytes: int,
    skip_existing: bool,
    timeout: float,
) -> list[dict[str, Any]]:
    output_root.mkdir(parents=True, exist_ok=True)
    semaphore = asyncio.Semaphore(concurrency)
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="apiary-vpe-") as tmp:
        work_dir = Path(tmp)
        # Mirror npm-client headers; some registry mirrors enforce UA filtering.
        headers = {
            "User-Agent": "apiary-train/0.3 (+https://github.com/ademczuk/apiary)",
            "Accept": "application/json,application/octet-stream",
        }
        async with httpx.AsyncClient(
            timeout=timeout, headers=headers, follow_redirects=True
        ) as client:
            tasks = [
                _process_one(
                    case,
                    output_root,
                    client,
                    work_dir,
                    registry,
                    max_tarball_bytes,
                    skip_existing,
                    semaphore,
                )
                for case in cases
            ]
            for fut in asyncio.as_completed(tasks):
                row = await fut
                if row is not None:
                    rows.append(row)
    return rows


def _write_manifest(output_root: Path, rows: list[dict[str, Any]]) -> Path:
    manifest = output_root / "manifest.jsonl"
    with manifest.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return manifest


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_method: dict[str, int] = {}
    n_with_changes = 0
    total_changes = 0
    for row in rows:
        method = row.get("extraction_method") or "unknown"
        by_method[method] = by_method.get(method, 0) + 1
        if (row.get("n_files_changed") or 0) > 0:
            n_with_changes += 1
            total_changes += row["n_files_changed"]
    return {
        "n_total": len(rows),
        "n_with_changes": n_with_changes,
        "n_files_changed_total": total_changes,
        "by_method": by_method,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scraped-cases",
        type=Path,
        default=Path("data/raw/scraped-ghsa/scraped-cases.jsonl"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/version-pairs/"),
    )
    parser.add_argument("--concurrency", type=int, default=6)
    parser.add_argument("--max-cases", type=int, default=0, help="0 = no cap")
    parser.add_argument("--skip-existing", action="store_true")
    parser.add_argument("--registry", default=DEFAULT_REGISTRY)
    parser.add_argument(
        "--max-tarball-bytes",
        type=int,
        default=MAX_TARBALL_BYTES,
        help=f"per-tarball cap in bytes (default {MAX_TARBALL_BYTES})",
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.scraped_cases.is_file():
        logger.error("scraped-cases not found: %s", args.scraped_cases)
        return 1

    cases = list(_iter_jsonl(args.scraped_cases))
    if args.max_cases:
        cases = cases[: args.max_cases]
    logger.info(
        "loaded %d scraped cases (concurrency=%d, max_tarball=%d bytes)",
        len(cases),
        args.concurrency,
        args.max_tarball_bytes,
    )

    rows = asyncio.run(
        _run(
            cases,
            args.output,
            args.concurrency,
            args.registry,
            args.max_tarball_bytes,
            args.skip_existing,
            args.timeout,
        )
    )

    manifest = _write_manifest(args.output, rows)
    summary = _summarize(rows)
    logger.info("manifest written: %s", manifest)
    logger.info("summary: %s", summary)
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
