"""Download the figshare NPM Malicious Package Study and unpack it.

DOI: 10.6084/m9.figshare.31869370
License: CC BY 4.0

The article has two files, both named NPMStudy.zip:
- 87.9 MB  (file id 63179326) — probably the curated subset
- 3.4 GB   (file id 63260731) — the full corpus

By default this script grabs the smaller archive so the team can iterate
quickly; pass --full to also pull the big one.

Usage:
    python scripts/download_figshare.py [--full] [--out data/raw/figshare]

TODO:
    - Compute SHA256 after download and compare to a known-good value
      (figshare API returns a md5 hash on each file record, prefer that).
    - Add resume support via Range requests.
    - Verify the unpacked layout matches what preprocess.py expects.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zipfile
from pathlib import Path

import requests
from tqdm import tqdm

ARTICLE_ID = 31869370
API_URL = f"https://api.figshare.com/v2/articles/{ARTICLE_ID}"


def fetch_article_metadata() -> dict:
    """Hit the figshare API for the article record (file ids, hashes, sizes)."""
    response = requests.get(API_URL, timeout=30)
    response.raise_for_status()
    return response.json()


def download_file(url: str, out_path: Path, expected_size: int | None = None) -> Path:
    """Stream a download with a progress bar. Returns the on-disk path."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(url, stream=True, timeout=60) as response:
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0)) or expected_size or 0
        with (
            out_path.open("wb") as f,
            tqdm(total=total, unit="B", unit_scale=True, desc=out_path.name) as bar,
        ):
            for chunk in response.iter_content(chunk_size=1 << 20):
                if chunk:
                    f.write(chunk)
                    bar.update(len(chunk))
    return out_path


def sha256_of(path: Path) -> str:
    """Compute a SHA256 for verification."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def unpack(archive: Path, dest: Path) -> None:
    """Unpack a zip into dest (idempotent)."""
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(dest)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", action="store_true", help="also fetch the 3.4 GB archive")
    parser.add_argument("--out", default="data/raw/figshare", help="output directory")
    parser.add_argument("--skip-unpack", action="store_true")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    meta = fetch_article_metadata()
    print(f"Article: {meta.get('title')}")
    print(f"License: {meta.get('license', {}).get('name')}")

    files = sorted(meta.get("files", []), key=lambda f: f["size"])
    if not files:
        print("ERROR: no files found in article record", file=sys.stderr)
        return 2

    # Smaller archive is the default; bigger only if --full
    targets = files if args.full else files[:1]

    for entry in targets:
        name = entry["name"]
        size = entry["size"]
        url = entry["download_url"]
        local = out_dir / f"{entry['id']}_{name}"
        if local.exists() and local.stat().st_size == size:
            print(f"SKIP (already present): {local}")
        else:
            print(f"DOWNLOAD: {name} ({size:,} bytes) -> {local}")
            download_file(url, local, expected_size=size)

        # TODO: compare sha256_of(local) against a pinned hash to detect corruption.
        if not args.skip_unpack and local.suffix == ".zip":
            print(f"UNPACK: {local}")
            unpack(local, out_dir / f"{entry['id']}_unpacked")

    return 0


if __name__ == "__main__":
    sys.exit(main())
