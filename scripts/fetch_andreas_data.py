"""Fetch Andreas's finetune data from Google Drive and build a manifest.

Three input modes:

    # gdown (works for publicly shared folders, no OAuth)
    python scripts/fetch_andreas_data.py \
        --drive-folder-id 1GaNVt0eP9k-BW_E0fuIdqd5gsvY2a1Mz \
        --output data/raw/andreas-finetune/ \
        --auth-method gdown

    # rclone (requires user to have a configured gdrive remote)
    python scripts/fetch_andreas_data.py \
        --rclone-remote gdrive:Apiary-Finetune \
        --output data/raw/andreas-finetune/ \
        --auth-method rclone

    # manual URL list (one direct download URL per line)
    python scripts/fetch_andreas_data.py \
        --url-list urls.txt \
        --output data/raw/andreas-finetune/ \
        --auth-method manual-url-list

After download:

* Any .zip / .tar / .tar.gz / .tgz archives are unpacked in place.
* The resulting tree is walked and ``manifest.json`` is written with file
  paths, types, sizes, and sha256.
* JSONL files are sampled for likely instruction-tuning keys
  (``messages``, ``prompt``/``completion``, ``input``/``output``) and the
  detected shape is logged.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger("apiary.fetch_andreas")

SFT_HINT_KEYS = {
    "messages",
    "prompt",
    "completion",
    "input",
    "output",
    "question",
    "answer",
    "instruction",
    "response",
}

ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")


def _which(tool: str) -> str | None:
    """Return the absolute path of ``tool`` on PATH, or None."""
    return shutil.which(tool)


def fetch_gdown(folder_id: str, output: Path) -> int:
    """Invoke ``gdown --folder`` for a publicly shared Drive folder."""
    if _which("gdown") is None:
        logger.error("gdown not installed; run: pip install gdown")
        return 2
    output.mkdir(parents=True, exist_ok=True)
    url = f"https://drive.google.com/drive/folders/{folder_id}"
    logger.info("gdown: fetching folder %s into %s", folder_id, output)
    proc = subprocess.run(
        ["gdown", "--folder", url, "-O", str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        logger.error("gdown failed (exit %d): %s", proc.returncode, proc.stderr.strip())
        logger.error(
            "common causes: folder is not publicly shared, requires sign-in, "
            "or rate-limited. Try rclone mode if you have a configured remote."
        )
        return proc.returncode
    return 0


def fetch_rclone(remote: str, output: Path) -> int:
    """Invoke ``rclone copy <remote> <output>``."""
    if _which("rclone") is None:
        logger.error("rclone not installed. See https://rclone.org/install/")
        return 2
    output.mkdir(parents=True, exist_ok=True)
    logger.info("rclone: copying %s into %s", remote, output)
    proc = subprocess.run(
        ["rclone", "copy", "--progress", remote, str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        logger.error("rclone failed (exit %d): %s", proc.returncode, proc.stderr.strip())
        logger.error(
            "if your gdrive remote is not configured, run: rclone config "
            "and follow the gdrive setup prompts before retrying."
        )
        return proc.returncode
    return 0


def fetch_manual(url_list: Path, output: Path) -> int:
    """Fetch a list of pre-shared direct URLs via httpx."""
    output.mkdir(parents=True, exist_ok=True)
    if not url_list.exists():
        logger.error("url list not found: %s", url_list)
        return 2
    urls = [
        line.strip()
        for line in url_list.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not urls:
        logger.error("url list is empty: %s", url_list)
        return 2
    logger.info("manual: downloading %d urls into %s", len(urls), output)
    with httpx.Client(follow_redirects=True, timeout=120.0) as client:
        for idx, url in enumerate(urls, start=1):
            name = url.split("/")[-1].split("?")[0] or f"file-{idx}.bin"
            dest = output / name
            logger.info("(%d/%d) %s -> %s", idx, len(urls), url, dest.name)
            try:
                with client.stream("GET", url) as resp:
                    resp.raise_for_status()
                    with dest.open("wb") as fh:
                        for chunk in resp.iter_bytes():
                            fh.write(chunk)
            except httpx.HTTPError as exc:
                logger.error("failed %s: %s", url, exc)
                return 1
    return 0


def unpack_archives(root: Path) -> list[Path]:
    """Unpack any zip/tar archives under ``root`` in place. Returns unpacked dirs."""
    extracted: list[Path] = []
    for path in list(root.rglob("*")):
        if not path.is_file():
            continue
        name_lower = path.name.lower()
        try:
            if name_lower.endswith(".zip"):
                target = path.parent / path.stem
                target.mkdir(exist_ok=True)
                with zipfile.ZipFile(path) as zf:
                    zf.extractall(target)
                logger.info("unpacked zip %s -> %s", path.name, target)
                extracted.append(target)
            elif name_lower.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2")):
                target = path.parent / path.stem.replace(".tar", "")
                target.mkdir(exist_ok=True)
                with tarfile.open(path) as tf:
                    tf.extractall(target)
                logger.info("unpacked tar %s -> %s", path.name, target)
                extracted.append(target)
        except (zipfile.BadZipFile, tarfile.TarError, OSError) as exc:
            logger.warning("could not unpack %s: %s", path, exc)
    return extracted


def _sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            buf = fh.read(chunk)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def _detect_sft_keys(path: Path, sample: int = 50) -> list[str]:
    """Sample up to ``sample`` lines of a JSONL file and collect SFT-shaped keys."""
    if path.suffix.lower() not in {".jsonl", ".ndjson"}:
        return []
    found: set[str] = set()
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for idx, line in enumerate(fh):
                if idx >= sample:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    found.update(set(rec.keys()) & SFT_HINT_KEYS)
    except OSError:
        return []
    return sorted(found)


def build_manifest(root: Path) -> dict[str, Any]:
    """Walk ``root`` and write ``manifest.json``."""
    entries: list[dict[str, Any]] = []
    sft_total = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "manifest.json":
            continue
        rel = path.relative_to(root).as_posix()
        size = path.stat().st_size
        suffix = "".join(path.suffixes).lower() or path.suffix.lower()
        kind = "unknown"
        for known in (".jsonl", ".ndjson", ".json", ".csv", ".parquet", ".txt", ".md"):
            if suffix.endswith(known):
                kind = known.lstrip(".")
                break
        for arch in ARCHIVE_SUFFIXES:
            if suffix.endswith(arch):
                kind = "archive"
                break
        try:
            digest = _sha256(path)
        except OSError as exc:
            logger.warning("could not hash %s: %s", path, exc)
            continue
        sft_keys = _detect_sft_keys(path) if kind in {"jsonl", "ndjson"} else []
        if sft_keys:
            sft_total += 1
        entries.append(
            {
                "path": rel,
                "kind": kind,
                "size_bytes": size,
                "sha256": digest,
                "sft_keys": sft_keys,
            }
        )
    manifest = {
        "root": str(root),
        "file_count": len(entries),
        "total_bytes": sum(e["size_bytes"] for e in entries),
        "sft_candidate_count": sft_total,
        "files": entries,
    }
    out = root / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info(
        "manifest: %d files, %d bytes, %d SFT-candidate JSONL files -> %s",
        manifest["file_count"],
        manifest["total_bytes"],
        sft_total,
        out,
    )
    return manifest


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fetch Andreas's finetune data from Google Drive")
    parser.add_argument("--drive-folder-id", help="Google Drive folder ID (gdown mode)")
    parser.add_argument("--rclone-remote", help="rclone remote path, e.g. gdrive:Apiary-Finetune")
    parser.add_argument("--url-list", type=Path, help="File of direct URLs (manual mode)")
    parser.add_argument("--output", required=True, type=Path, help="Output directory")
    parser.add_argument(
        "--auth-method",
        choices=("gdown", "rclone", "manual-url-list"),
        default="gdown",
        help="How to obtain the files",
    )
    parser.add_argument("--skip-fetch", action="store_true", help="Only build manifest")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    output = Path(args.output)
    if not args.skip_fetch:
        if args.auth_method == "gdown":
            if not args.drive_folder_id:
                logger.error("gdown mode requires --drive-folder-id")
                return 2
            rc = fetch_gdown(args.drive_folder_id, output)
        elif args.auth_method == "rclone":
            if not args.rclone_remote:
                logger.error("rclone mode requires --rclone-remote")
                return 2
            rc = fetch_rclone(args.rclone_remote, output)
        else:
            if not args.url_list:
                logger.error("manual-url-list mode requires --url-list")
                return 2
            rc = fetch_manual(args.url_list, output)
        if rc != 0:
            return rc
    unpack_archives(output)
    manifest = build_manifest(output)
    print(json.dumps({k: v for k, v in manifest.items() if k != "files"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
