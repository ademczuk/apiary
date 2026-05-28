"""Fetch the Datadog malicious-software-packages-dataset and extract npm samples.

Source repo: https://github.com/DataDog/malicious-software-packages-dataset
License: Apache-2.0
Size: roughly 27,489 packages across npm and pypi; the npm slice runs around
17,600 packages (about 64 percent of the total).

Each package ships as a password-encrypted ZIP under
``samples/npm/<intent_class>/<package>/<version>/<YYYY-MM-DD>-<pkg>-v<ver>.zip``
with the canonical password ``infected``. A ``manifest.json`` at
``samples/npm/manifest.json`` enumerates which packages have malicious intent
(value ``null``) versus a compromised library (value is a list of affected
versions).

Strategy:

1. Shallow + sparse clone the upstream repo, restricted to ``samples/npm/`` so
   pypi / other ecosystems are skipped.
2. Parse the npm manifest, walk the matching encrypted ZIPs.
3. Extract using ``zipfile.ZipFile`` with ``pwd=b"infected"`` into
   ``<output>/extracted/<package>/<version>/``.
4. Stamp a ``MALICIOUS_DO_NOT_INSTALL.txt`` warning in the output root and
   beside every extracted package.
5. Emit ``manifest.jsonl``, one line per extracted package.

CLI:

    python scripts/fetch_datadog_dataset.py \\
        --output data/raw/datadog-malicious/ \\
        --ecosystem npm \\
        --max-packages 500

Safety:

* Never execute any extracted file. The extracted tree is gitignored.
* The output directory is annotated with a ``MALICIOUS_DO_NOT_INSTALL.txt``
  warning so a casual ``ls`` makes the danger obvious.
* Idempotent: rerunning skips already-extracted packages by checking the
  extraction marker file.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("apiary.fetch_datadog")

REPO_URL = "https://github.com/DataDog/malicious-software-packages-dataset.git"
ZIP_PASSWORD = b"infected"
SUPPORTED_ECOSYSTEMS = ("npm", "pypi")

# Subdirectories under samples/<ecosystem>/. ``malicious_intent`` is the bulk
# of the corpus (packages that exist only to attack); ``compromised_lib`` is
# the smaller but higher-signal slice (real libraries that were briefly
# hijacked). We walk both.
_INTENT_DIRS = ("malicious_intent", "compromised_lib")

_FILENAME_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})-(?P<pkg>.+)-v(?P<ver>[^/]+)\.zip$"
)

WARNING_BANNER = """\
APIARY MALICIOUS PACKAGE CORPUS
=================================

This directory contains live malicious npm packages extracted from the
Datadog malicious-software-packages-dataset. They are intended for
training and detection research only.

DO NOT:
  * `npm install` any package here
  * Execute, source, or import any file
  * Open a script in an editor that auto-runs hooks (Cursor, VS Code with
    eager extensions can fetch package metadata that triggers behaviour)

The original ZIPs were password-protected with `infected`. They were
extracted in this controlled location specifically to study them. Treat
every file as live ordnance.

Source: https://github.com/DataDog/malicious-software-packages-dataset
License: Apache-2.0
"""


def _run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    logger.debug("exec: %s (cwd=%s)", " ".join(cmd), cwd)
    return subprocess.run(cmd, cwd=cwd, check=check, capture_output=True, text=True)


def ensure_sparse_clone(clone_dir: Path, ecosystem: str) -> Path:
    """Clone (or refresh) the Datadog repo with sparse checkout for one ecosystem.

    Returns the absolute path of the ``samples/<ecosystem>/`` subtree.

    Windows note: the corpus contains a handful of filenames that Windows
    refuses (trailing dot, reserved character). We use a two-stage clone
    with ``--no-checkout`` then narrow sparse-checkout to the ecosystem
    before materializing the tree, and tolerate per-file checkout failures
    so the bulk of the corpus is still usable.
    """
    sparse_path = f"samples/{ecosystem}/"
    if (clone_dir / ".git").is_dir():
        logger.info("reusing existing clone at %s", clone_dir)
        try:
            _run(["git", "sparse-checkout", "set", sparse_path], cwd=clone_dir)
            _run(
                ["git", "-c", "core.protectNTFS=false", "pull", "--ff-only", "origin", "main"],
                cwd=clone_dir,
                check=False,
            )
        except subprocess.CalledProcessError as exc:
            logger.warning(
                "git pull failed (%s); continuing with existing tree",
                exc.stderr.strip(),
            )
    else:
        logger.info("cloning %s into %s (sparse=%s)", REPO_URL, clone_dir, sparse_path)
        clone_dir.parent.mkdir(parents=True, exist_ok=True)
        # Stage 1: clone with no checkout so we can scope sparse-checkout first.
        _run(
            [
                "git",
                "clone",
                "--depth", "1",
                "--filter=blob:none",
                "--sparse",
                "--no-checkout",
                REPO_URL,
                str(clone_dir),
            ]
        )
        _run(["git", "sparse-checkout", "set", sparse_path], cwd=clone_dir)
        # Stage 2: checkout the narrowed tree. core.protectNTFS=false lets
        # Windows accept paths that would otherwise hard-fail (trailing dots,
        # reserved characters). Per-file failures are non-fatal: the few zips
        # that don't materialize are dropped from the working tree but the
        # rest are usable.
        try:
            _run(
                [
                    "git",
                    "-c", "core.protectNTFS=false",
                    "checkout",
                    "HEAD",
                ],
                cwd=clone_dir,
            )
        except subprocess.CalledProcessError as exc:
            logger.warning(
                "git checkout reported errors (typically Windows-illegal paths); "
                "continuing with partial tree. stderr=%s",
                exc.stderr.strip() if exc.stderr else "",
            )

    eco_dir = clone_dir / "samples" / ecosystem
    if not eco_dir.is_dir():
        raise RuntimeError(
            f"sparse-checkout did not materialize {eco_dir}. "
            f"Check ecosystem '{ecosystem}' exists upstream."
        )
    return eco_dir


def load_manifest(eco_dir: Path) -> dict[str, list[str] | None]:
    """Read the ecosystem manifest.json mapping package -> versions (or None)."""
    manifest_path = eco_dir / "manifest.json"
    if not manifest_path.is_file():
        raise RuntimeError(f"manifest not found: {manifest_path}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def iter_zip_files(eco_dir: Path) -> Iterator[Path]:
    """Walk every encrypted ZIP under samples/<ecosystem>/<intent>/."""
    for intent in _INTENT_DIRS:
        intent_dir = eco_dir / intent
        if not intent_dir.is_dir():
            continue
        for path in intent_dir.rglob("*.zip"):
            if path.is_file():
                yield path


def _parse_zip_name(path: Path) -> dict | None:
    """Pull date / package / version out of the canonical filename."""
    match = _FILENAME_RE.match(path.name)
    if not match:
        return None
    return {
        "captured_date": match.group("date"),
        "package_filename": match.group("pkg"),
        "version": match.group("ver"),
    }


def _intent_class(zip_path: Path, eco_dir: Path) -> str:
    """Identify whether the zip lives under malicious_intent or compromised_lib."""
    rel = zip_path.relative_to(eco_dir).parts
    if rel:
        return rel[0]
    return "unknown"


def _scoped_package_name(filename_pkg: str) -> str:
    """Convert filename-scoped name `@scope@name` back to npm `@scope/name`."""
    if filename_pkg.startswith("@"):
        # `@scope@name` -> `@scope/name`. There may be at most one second `@`.
        rest = filename_pkg[1:]
        if "@" in rest:
            scope, _, name = rest.partition("@")
            return f"@{scope}/{name}"
    return filename_pkg


def _safe_dirname(name: str) -> str:
    """Drop characters that don't render cleanly as a Windows path segment."""
    return re.sub(r'[<>:"/\\|?*]', "_", name)


def safe_extract_zip(zip_path: Path, target_dir: Path) -> list[str]:
    """Extract an encrypted ZIP without ever executing its contents.

    Returns the list of entry names extracted. Skips any zip member whose
    resolved path would escape ``target_dir`` (zip-slip defence).
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            name = info.filename
            # Reject absolute paths or parent-escape components.
            if name.startswith(("/", "\\")) or ".." in Path(name).parts:
                logger.warning("zip-slip: skipping %s in %s", name, zip_path)
                continue
            # Compute the final on-disk path and refuse if it leaves target_dir.
            dest = (target_dir / name).resolve()
            if target_dir.resolve() not in dest.parents and dest != target_dir.resolve():
                logger.warning("zip escape: skipping %s in %s", name, zip_path)
                continue
            try:
                zf.extract(info, path=target_dir, pwd=ZIP_PASSWORD)
                extracted.append(name)
            except (RuntimeError, zipfile.BadZipFile) as exc:
                logger.warning("extract failed for %s in %s: %s", name, zip_path, exc)
                continue
    return extracted


def _intent_label(manifest: dict, package: str, version: str, intent_class: str) -> str:
    """Map the manifest entry into a coarse intent label."""
    if intent_class == "compromised_lib":
        return "compromised_lib"
    if package in manifest:
        entry = manifest[package]
        if entry is None:
            return "malicious_intent_all_versions"
        if isinstance(entry, list) and version in entry:
            return "compromised_lib_listed"
    return "malicious_intent"


def write_safety_banner(target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    (target / "MALICIOUS_DO_NOT_INSTALL.txt").write_text(WARNING_BANNER, encoding="utf-8")


def fetch(
    clone_dir: Path,
    output_dir: Path,
    ecosystem: str,
    max_packages: int | None,
    refresh_clone: bool,
) -> dict:
    """Top-level pipeline. Returns stats dict."""
    if refresh_clone and clone_dir.exists():
        logger.info("removing cached clone at %s", clone_dir)
        shutil.rmtree(clone_dir, ignore_errors=True)

    eco_dir = ensure_sparse_clone(clone_dir, ecosystem)
    manifest = load_manifest(eco_dir)
    logger.info("manifest carries %d package entries", len(manifest))

    output_dir.mkdir(parents=True, exist_ok=True)
    write_safety_banner(output_dir)
    extracted_root = output_dir / "extracted"
    extracted_root.mkdir(exist_ok=True)
    write_safety_banner(extracted_root)

    manifest_out_path = output_dir / "manifest.jsonl"
    seen = 0
    written = 0
    skipped_existing = 0
    skipped_bad_name = 0
    failures = 0
    intent_counts: dict[str, int] = {}

    # Stable iteration so --max-packages cut-off is reproducible.
    zip_paths = sorted(iter_zip_files(eco_dir))
    logger.info("walking %d candidate ZIPs under %s", len(zip_paths), eco_dir)

    with manifest_out_path.open("w", encoding="utf-8") as manifest_out:
        for zip_path in zip_paths:
            seen += 1
            if max_packages is not None and written >= max_packages:
                break
            meta = _parse_zip_name(zip_path)
            if meta is None:
                skipped_bad_name += 1
                continue
            package = _scoped_package_name(meta["package_filename"])
            version = meta["version"]
            intent_class = _intent_class(zip_path, eco_dir)

            # extracted/<safe-pkg>/<safe-ver>/
            pkg_dir = extracted_root / _safe_dirname(package) / _safe_dirname(version)
            marker = pkg_dir / ".apiary_extracted"
            if marker.is_file():
                skipped_existing += 1
                manifest_entry = json.loads(marker.read_text(encoding="utf-8"))
                manifest_out.write(json.dumps(manifest_entry, ensure_ascii=False) + "\n")
                written += 1
                intent_counts[manifest_entry["intent_label"]] = (
                    intent_counts.get(manifest_entry["intent_label"], 0) + 1
                )
                continue

            try:
                extracted_entries = safe_extract_zip(zip_path, pkg_dir)
            except (zipfile.BadZipFile, OSError) as exc:
                logger.warning("zip open failed for %s: %s", zip_path, exc)
                failures += 1
                continue

            intent_label = _intent_label(manifest, package, version, intent_class)
            write_safety_banner(pkg_dir)

            entry = {
                "schema_version": "apiary.datadog_extracted.v1",
                "ecosystem": ecosystem,
                "package": package,
                "version": version,
                "captured_date": meta["captured_date"],
                "intent_class": intent_class,
                "intent_label": intent_label,
                "source_zip": str(zip_path.relative_to(clone_dir).as_posix()),
                "extracted_to": str(pkg_dir.relative_to(output_dir).as_posix()),
                "extracted_files": extracted_entries,
                "extracted_file_count": len(extracted_entries),
                "extracted_at": datetime.now(timezone.utc).isoformat(),
            }
            marker.write_text(json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8")
            manifest_out.write(json.dumps(entry, ensure_ascii=False) + "\n")

            written += 1
            intent_counts[intent_label] = intent_counts.get(intent_label, 0) + 1

    config_blob = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "repo": REPO_URL,
        "ecosystem": ecosystem,
        "max_packages": max_packages,
        "clone_dir": str(clone_dir),
        "stats": {
            "candidates_seen": seen,
            "written": written,
            "skipped_existing": skipped_existing,
            "skipped_bad_name": skipped_bad_name,
            "failures": failures,
            "intent_distribution": intent_counts,
        },
    }
    (output_dir / "fetch-config.json").write_text(
        json.dumps(config_blob, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return config_blob


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/raw/datadog-malicious"),
        help="Output directory; will hold extracted/, manifest.jsonl, fetch-config.json.",
    )
    parser.add_argument(
        "--ecosystem",
        choices=SUPPORTED_ECOSYSTEMS,
        default="npm",
        help="Which ecosystem subtree to fetch.",
    )
    parser.add_argument(
        "--max-packages",
        type=int,
        default=500,
        help="Cap on packages to extract. Use 0 for unlimited.",
    )
    parser.add_argument(
        "--clone-dir",
        type=Path,
        default=None,
        help="Where to keep the sparse clone. Defaults to a stable path in the temp dir.",
    )
    parser.add_argument(
        "--refresh-clone",
        action="store_true",
        help="Delete the cached clone before fetching.",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    clone_dir = args.clone_dir or Path(tempfile.gettempdir()) / "datadog-malpkg"
    max_packages = None if args.max_packages == 0 else args.max_packages

    try:
        config = fetch(
            clone_dir=clone_dir,
            output_dir=args.output,
            ecosystem=args.ecosystem,
            max_packages=max_packages,
            refresh_clone=args.refresh_clone,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("git command failed: %s\nstderr: %s", " ".join(exc.cmd), exc.stderr)
        return 2
    except RuntimeError as exc:
        logger.error("%s", exc)
        return 3

    stats = config["stats"]
    logger.info(
        "done: wrote %d entries (skipped_existing=%d, failures=%d) to %s",
        stats["written"],
        stats["skipped_existing"],
        stats["failures"],
        args.output / "manifest.jsonl",
    )
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
