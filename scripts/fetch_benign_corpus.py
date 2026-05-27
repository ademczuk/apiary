"""Fetch a corpus of popular benign npm packages for use as negatives.

Queries the npms.io search API for top packages, downloads the latest tarball
of each from the npm registry, unpacks into per-package directories, and
emits a manifest.

Usage:
    python scripts/fetch_benign_corpus.py \
        --output data/raw/benign-packages/ \
        --count 2000 \
        --source top-downloads \
        --max-size-mb 5 \
        --max-workers 8
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import sys
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger("fetch_benign_corpus")

NPMS_SEARCH_URL = "https://api.npms.io/v2/search"
NPM_REGISTRY_URL = "https://registry.npmjs.org"
PAGE_SIZE = 250


def setup_logging(verbose: bool = False) -> None:
    """Configure root logger."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def query_top_packages(count: int, source: str) -> list[str]:
    """Return up to `count` package names from npms.io sorted by popularity."""
    names: list[str] = []
    offset = 0
    score_field = {
        "top-downloads": "popularity",
        "top-quality": "quality",
        "top-maintenance": "maintenance",
    }.get(source, "popularity")

    while len(names) < count:
        page = min(PAGE_SIZE, count - len(names))
        params = {
            "q": "boost-exact:false",
            "size": page,
            "from": offset,
            f"{score_field}-weight": 100,
            "popularity-weight": 100,
        }
        try:
            resp = requests.get(NPMS_SEARCH_URL, params=params, timeout=30)
        except requests.RequestException as exc:
            logger.warning("npms.io request failed at offset %d: %s", offset, exc)
            break
        if resp.status_code == 429:
            wait = 2 ** min(5, (offset // PAGE_SIZE))
            logger.warning("npms.io 429, sleeping %ds", wait)
            time.sleep(wait)
            continue
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", [])
        if not results:
            break
        for entry in results:
            name = entry.get("package", {}).get("name")
            if name:
                names.append(name)
        offset += page
        # Be polite to the public API.
        time.sleep(0.2)
    return names[:count]


def fetch_tarball_url(name: str) -> tuple[str | None, str | None]:
    """Return (tarball_url, latest_version) for `name`, or (None, None)."""
    url = f"{NPM_REGISTRY_URL}/{name.replace('/', '%2F')}"
    backoff = 1
    for attempt in range(5):
        try:
            resp = requests.get(url, timeout=30)
        except requests.RequestException as exc:
            logger.debug("registry GET %s failed: %s", name, exc)
            time.sleep(backoff)
            backoff *= 2
            continue
        if resp.status_code == 429:
            logger.warning("npm 429 for %s, sleeping %ds", name, backoff)
            time.sleep(backoff)
            backoff *= 2
            continue
        if resp.status_code == 404:
            return None, None
        resp.raise_for_status()
        meta = resp.json()
        latest = meta.get("dist-tags", {}).get("latest")
        if not latest:
            return None, None
        version_meta = meta.get("versions", {}).get(latest, {})
        tarball = version_meta.get("dist", {}).get("tarball")
        return tarball, latest
    return None, None


def fetch_and_unpack(
    name: str,
    output_root: Path,
    max_size_mb: int,
) -> dict[str, Any] | None:
    """Download and unpack one npm tarball into output_root/<safe_name>/."""
    safe = name.replace("/", "__").replace("@", "")
    target = output_root / safe
    if target.exists() and any(target.iterdir()):
        # Already fetched.
        return {
            "name": name,
            "path": str(target),
            "skipped": True,
            "reason": "already-fetched",
        }
    tarball_url, version = fetch_tarball_url(name)
    if not tarball_url:
        return {"name": name, "skipped": True, "reason": "no-tarball"}

    try:
        resp = requests.get(tarball_url, timeout=60, stream=True)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return {"name": name, "skipped": True, "reason": f"download-error:{exc}"}

    content_length = resp.headers.get("content-length")
    if content_length and int(content_length) > max_size_mb * 1024 * 1024:
        return {
            "name": name,
            "skipped": True,
            "reason": f"too-large:{content_length}",
        }

    buf = io.BytesIO()
    bytes_read = 0
    cap = max_size_mb * 1024 * 1024
    for chunk in resp.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        bytes_read += len(chunk)
        if bytes_read > cap:
            return {"name": name, "skipped": True, "reason": "stream-over-cap"}
        buf.write(chunk)
    buf.seek(0)

    target.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=buf, mode="r:gz") as tf:
            for member in tf.getmembers():
                if member.isdir():
                    continue
                if not _is_safe_path(member.name):
                    continue
                # npm tarballs put files under a "package/" prefix; strip it.
                rel = member.name
                if rel.startswith("package/"):
                    rel = rel[len("package/"):]
                if not rel:
                    continue
                dest = target / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                f = tf.extractfile(member)
                if f is None:
                    continue
                dest.write_bytes(f.read())
    except (tarfile.TarError, EOFError) as exc:
        return {"name": name, "skipped": True, "reason": f"untar-error:{exc}"}

    return {
        "name": name,
        "path": str(target),
        "version": version,
        "size_bytes": bytes_read,
        "skipped": False,
    }


def _is_safe_path(name: str) -> bool:
    """Reject zip-slip-style paths and absolute paths."""
    if name.startswith("/") or name.startswith("\\"):
        return False
    if ".." in name.replace("\\", "/").split("/"):
        return False
    return True


def write_manifest(manifest_path: Path, entries: list[dict[str, Any]]) -> None:
    """Write the manifest.jsonl (one line per successfully fetched package)."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI args."""
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--count", type=int, default=2000)
    p.add_argument("--source", default="top-downloads",
                   choices=["top-downloads", "top-quality", "top-maintenance"])
    p.add_argument("--max-size-mb", type=int, default=5)
    p.add_argument("--max-workers", type=int, default=8)
    p.add_argument("--verbose", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    setup_logging(args.verbose)

    args.output.mkdir(parents=True, exist_ok=True)
    logger.info("Querying npms.io for top %d packages (%s)", args.count, args.source)
    names = query_top_packages(args.count, args.source)
    logger.info("Got %d candidate package names", len(names))
    if not names:
        logger.error("No candidates from npms.io; aborting.")
        return 1

    start = time.time()
    entries: list[dict[str, Any]] = []
    done = 0
    workers = max(1, args.max_workers)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(fetch_and_unpack, name, args.output, args.max_size_mb): name
            for name in names
        }
        for fut in as_completed(futures):
            done += 1
            try:
                entry = fut.result()
            except Exception as exc:  # noqa: BLE001
                logger.exception("fetch failed: %s", exc)
                continue
            if entry is None:
                continue
            if not entry.get("skipped"):
                entries.append(entry)
            if done % 50 == 0:
                rate = done / max(1e-6, time.time() - start)
                logger.info(
                    "Progress: %d/%d kept=%d rate=%.1f pkg/s",
                    done, len(names), len(entries), rate,
                )

    manifest = args.output / "manifest.jsonl"
    write_manifest(manifest, entries)
    logger.info(
        "Done. fetched=%d skipped=%d manifest=%s",
        len(entries), len(names) - len(entries), manifest,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
