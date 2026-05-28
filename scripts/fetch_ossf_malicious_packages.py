"""Fetch the OSSF malicious-packages corpus and emit per-record JSON.

Source repo: https://github.com/ossf/malicious-packages (Apache 2.0).
Holds the OSSF community's curated catalog of malicious package reports
in OSV format. The npm slice alone runs to roughly 213k records as of
2026-05 and is the second major real-world data source after GHSA for
apiary's training pipeline.

Strategy:

1. Clone (or reuse) the upstream repo with a sparse checkout limited to
   ``osv/malicious/<ecosystem>/``. This skips the other ecosystems
   (PyPI, Composer, etc.) and, critically, sidesteps the colon-bearing
   paths under ``osv/withdrawn/`` that Windows refuses to materialize.
2. Walk the ecosystem subtree, parse each OSV JSON file.
3. Apply ``--since`` and ``--max-records`` filters; emit one normalized
   case JSON per record plus a JSONL manifest with summary rows.

CLI:

    python scripts/fetch_ossf_malicious_packages.py \\
        --output data/raw/ossf-malicious-packages/ \\
        --ecosystem npm \\
        --since 2024-01-01 \\
        --max-records 5000

Outputs:

    data/raw/ossf-malicious-packages/
        records/<ossf_id>.json    one OSV record per file
        manifest.jsonl            one summary line per record
        fetch-config.json         capture of the CLI args + clone state

Idempotent: rerunning with the same args refreshes the clone with
``git pull`` rather than recloning.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("apiary.fetch_ossf")

REPO_URL = "https://github.com/ossf/malicious-packages.git"
SUPPORTED_ECOSYSTEMS = ("npm", "pypi", "rubygems", "crates.io", "go", "packagist", "nuget")

# Windows-safe characters only; OSSF IDs are MAL-YYYY-NNNN so they're already safe
# but we run them through this guard just in case the schema grows.
_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9._-]")


def _run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    logger.debug("exec: %s (cwd=%s)", " ".join(cmd), cwd)
    return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)


def ensure_sparse_clone(clone_dir: Path, ecosystem: str) -> Path:
    """Clone (or refresh) the OSSF repo with a sparse checkout for one ecosystem.

    Returns the absolute path of the ecosystem subtree.
    """
    sparse_path = f"osv/malicious/{ecosystem}/"
    if (clone_dir / ".git").is_dir():
        logger.info("reusing existing clone at %s", clone_dir)
        try:
            _run(["git", "sparse-checkout", "set", sparse_path], cwd=clone_dir)
            _run(["git", "pull", "--ff-only", "origin", "main"], cwd=clone_dir)
        except subprocess.CalledProcessError as exc:
            logger.warning("git pull failed (%s); continuing with existing tree", exc.stderr.strip())
    else:
        logger.info("cloning %s into %s (sparse=%s)", REPO_URL, clone_dir, sparse_path)
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        _run([
            "git",
            "clone",
            "--depth", "1",
            "--filter=blob:none",
            "--sparse",
            REPO_URL,
            str(clone_dir),
        ])
        _run(["git", "sparse-checkout", "set", sparse_path], cwd=clone_dir)

    eco_dir = clone_dir / "osv" / "malicious" / ecosystem
    if not eco_dir.is_dir():
        raise RuntimeError(
            f"sparse-checkout did not materialize {eco_dir}. "
            f"Check that ecosystem '{ecosystem}' exists upstream."
        )
    return eco_dir


def iter_osv_files(ecosystem_dir: Path) -> Iterator[Path]:
    """Yield every *.json file under an ecosystem subtree."""
    for path in ecosystem_dir.rglob("*.json"):
        if path.is_file():
            yield path


def parse_osv(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("skip unreadable record %s: %s", path, exc)
        return None


def _record_date(record: dict) -> datetime | None:
    """Pick the most useful date for filtering / sorting."""
    for field in ("published", "modified"):
        raw = record.get(field)
        if not raw:
            continue
        try:
            # OSV uses RFC3339 with a Z suffix; .replace handles the suffix
            return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
    return None


def _safe_id(rid: str) -> str:
    return _SAFE_ID_RE.sub("_", rid)[:120]


def _summarize(record: dict, source_path: Path) -> dict:
    """Build a one-line manifest summary."""
    affected = record.get("affected") or []
    pkg_name: str | None = None
    versions: list[str] = []
    cwes: list[str] = []
    for entry in affected:
        pkg = entry.get("package") or {}
        if pkg_name is None:
            pkg_name = pkg.get("name")
        versions.extend(entry.get("versions") or [])
        for cwe in (entry.get("database_specific") or {}).get("cwes") or []:
            cwe_id = cwe.get("cweId")
            if cwe_id:
                cwes.append(cwe_id)

    aliases = record.get("aliases") or []
    ghsa_ids = [a for a in aliases if isinstance(a, str) and a.startswith("GHSA-")]
    return {
        "ossf_id": record.get("id"),
        "package": pkg_name,
        "ecosystem": (affected[0].get("package") or {}).get("ecosystem") if affected else None,
        "aliases": aliases,
        "ghsa_ids": ghsa_ids,
        "summary": record.get("summary"),
        "published": record.get("published"),
        "modified": record.get("modified"),
        "version_count": len(versions),
        "cwe_ids": sorted(set(cwes)),
        "source_path": str(source_path.as_posix()),
    }


def filter_and_emit(
    records: list[tuple[Path, dict]],
    *,
    since: datetime | None,
    max_records: int | None,
    output_dir: Path,
) -> dict:
    """Apply filters and write records + manifest. Returns stats dict."""
    records_dir = output_dir / "records"
    records_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.jsonl"

    candidates: list[tuple[datetime | None, Path, dict]] = []
    skipped_no_date = 0
    skipped_too_old = 0
    for path, record in records:
        when = _record_date(record)
        if since is not None:
            if when is None:
                skipped_no_date += 1
                continue
            if when < since:
                skipped_too_old += 1
                continue
        candidates.append((when, path, record))

    # Newest first so --max-records keeps recent entries
    candidates.sort(key=lambda triple: triple[0] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    if max_records is not None:
        candidates = candidates[:max_records]

    written = 0
    by_year: dict[str, int] = {}
    with manifest_path.open("w", encoding="utf-8") as manifest_fh:
        for when, path, record in candidates:
            rid = record.get("id")
            if not isinstance(rid, str) or not rid:
                logger.warning("skip record without id at %s", path)
                continue
            target = records_dir / f"{_safe_id(rid)}.json"
            target.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
            summary = _summarize(record, path)
            manifest_fh.write(json.dumps(summary, ensure_ascii=False) + "\n")
            written += 1
            if when:
                by_year[str(when.year)] = by_year.get(str(when.year), 0) + 1

    return {
        "candidates_seen": len(records),
        "written": written,
        "skipped_no_date": skipped_no_date,
        "skipped_too_old": skipped_too_old,
        "by_year": dict(sorted(by_year.items())),
        "manifest": str(manifest_path),
        "records_dir": str(records_dir),
    }


def _parse_since(raw: str | None) -> datetime | None:
    if not raw:
        return None
    try:
        # Accept YYYY-MM-DD or full RFC3339
        if len(raw) == 10:
            return datetime.strptime(raw, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid --since value '{raw}': {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/ossf-malicious-packages"),
        help="Output directory (will hold records/ and manifest.jsonl).",
    )
    parser.add_argument(
        "--ecosystem",
        choices=SUPPORTED_ECOSYSTEMS,
        default="npm",
        help="Which ecosystem subtree to ingest.",
    )
    parser.add_argument(
        "--since",
        type=_parse_since,
        default=None,
        help="Lower-bound date filter (YYYY-MM-DD or RFC3339). Filters on published/modified.",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=None,
        help="Cap the number of records written. Sorted newest-first.",
    )
    parser.add_argument(
        "--clone-dir",
        type=Path,
        default=None,
        help="Where to keep the sparse clone. Defaults to a stable path in the user temp dir.",
    )
    parser.add_argument(
        "--refresh-clone",
        action="store_true",
        help="Delete the cached clone before fetching (forces a full re-fetch).",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    clone_dir = args.clone_dir or Path(tempfile.gettempdir()) / "ossf-malpkg"
    if args.refresh_clone and clone_dir.exists():
        logger.info("removing existing clone at %s", clone_dir)
        shutil.rmtree(clone_dir, ignore_errors=True)

    try:
        eco_dir = ensure_sparse_clone(clone_dir, args.ecosystem)
    except subprocess.CalledProcessError as exc:
        logger.error("git command failed: %s\nstderr: %s", " ".join(exc.cmd), exc.stderr)
        return 2

    logger.info("walking %s for OSV records", eco_dir)
    records: list[tuple[Path, dict]] = []
    for path in iter_osv_files(eco_dir):
        record = parse_osv(path)
        if record is None:
            continue
        records.append((path, record))
    logger.info("parsed %d OSV records", len(records))

    args.output.mkdir(parents=True, exist_ok=True)
    stats = filter_and_emit(
        records,
        since=args.since,
        max_records=args.max_records,
        output_dir=args.output,
    )
    config_blob = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "repo": REPO_URL,
        "ecosystem": args.ecosystem,
        "since": args.since.isoformat() if args.since else None,
        "max_records": args.max_records,
        "clone_dir": str(clone_dir),
        "stats": stats,
    }
    (args.output / "fetch-config.json").write_text(
        json.dumps(config_blob, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    logger.info("done: wrote %d records to %s", stats["written"], stats["records_dir"])
    logger.info("manifest: %s", stats["manifest"])
    logger.info("by_year: %s", stats["by_year"])
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
