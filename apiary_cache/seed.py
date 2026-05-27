"""Pre-audit a corpus of popular npm packages into the proxy cache.

Two entry points:

* ``seed_from_top_packages`` - pull the top-N most-downloaded packages from
  npms.io (using the existing fetch_benign_corpus machinery), download each
  tarball, run the policy gate and optional LLM audit, write the verdict
  beside the cached tarball.
* ``seed_from_list`` - read ``pkg@version`` lines from a file and seed only
  those.

Per-package output lands at::

    data/proxy-cache/<pkg>/<ver>/<file>.tgz
    data/proxy-cache/<pkg>/<ver>/.audit.json

The proxy reads ``.audit.json`` opportunistically; if absent, it falls back
to a live policy check at serve time.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from apiary_auditors import AuditBackend, build_audit_prompt, get_backend
from apiary_policy import decide_policy
from apiary_quarantine import load_quarantine_db

logger = logging.getLogger("apiary.cache.seed")

NPM_REGISTRY = "https://registry.npmjs.org"
DEFAULT_CACHE_DIR = Path("data/proxy-cache")


@dataclass
class SeedResult:
    package: str
    version: str
    verdict: str
    audit_verdict: str | None
    bytes: int
    error: str | None = None


def _query_top_packages(count: int) -> list[str]:
    """Thin wrapper around the existing benign-corpus puller."""
    # Import lazily so the package compiles without ``requests`` installed.
    try:
        from scripts.fetch_benign_corpus import query_top_packages
    except ImportError as exc:
        raise RuntimeError(
            "scripts.fetch_benign_corpus not importable; install requests"
        ) from exc
    return query_top_packages(count=count, source="top-downloads")


def _latest_version(metadata: dict[str, Any]) -> str | None:
    dist_tags = metadata.get("dist-tags") or {}
    latest = dist_tags.get("latest")
    if isinstance(latest, str):
        return latest
    versions = metadata.get("versions") or {}
    if isinstance(versions, dict) and versions:
        return sorted(versions.keys())[-1]
    return None


def _fetch_metadata(client: httpx.Client, package: str) -> dict[str, Any]:
    resp = client.get(f"{NPM_REGISTRY}/{package}")
    resp.raise_for_status()
    return resp.json()


def _fetch_tarball(
    client: httpx.Client, metadata: dict[str, Any], version: str
) -> tuple[bytes, str]:
    block = (metadata.get("versions") or {}).get(version) or {}
    dist = block.get("dist") or {}
    url = dist.get("tarball")
    if not url:
        raise RuntimeError(f"no tarball url for version {version}")
    resp = client.get(url)
    resp.raise_for_status()
    filename = url.rsplit("/", 1)[-1]
    return resp.content, filename


def _package_dir(cache_dir: Path, package: str, version: str) -> Path:
    safe = package.replace("/", os.sep)
    return cache_dir / safe / version


def _store_tarball(target_dir: Path, filename: str, payload: bytes) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / filename).write_bytes(payload)


def _safe_extract(tarball_path: Path, into: Path) -> None:
    """Extract npm tarball validating each member; rejects path-traversal."""
    import tarfile

    into.mkdir(parents=True, exist_ok=True)
    base = into.resolve()
    with tarfile.open(tarball_path, mode="r:*") as tf:
        for member in tf.getmembers():
            name = member.name
            if name.startswith("/") or ".." in Path(name).parts or os.path.isabs(name):
                logger.warning("skipping unsafe tarball member: %s", name)
                continue
            if member.issym() or member.islnk():
                logger.warning("skipping link member: %s", name)
                continue
            target = (into / name).resolve()
            try:
                target.relative_to(base)
            except ValueError:
                logger.warning("skipping out-of-tree member: %s", name)
                continue
            tf.extract(member, into)


def _audit_one(
    package: str,
    version: str,
    metadata: dict[str, Any],
    tarball_bytes: bytes,
    tarball_filename: str,
    cache_dir: Path,
    quarantine_db: dict[str, Any],
    audit_backend: AuditBackend | None,
    min_age_days: int,
) -> SeedResult:
    target_dir = _package_dir(cache_dir, package, version)
    _store_tarball(target_dir, tarball_filename, tarball_bytes)

    decision = decide_policy(
        package=package,
        version=version,
        metadata=metadata,
        tarball_bytes=tarball_bytes,
        quarantine_db=quarantine_db,
        min_age_days=min_age_days,
    )

    audit_verdict: str | None = None
    audit_payload: dict[str, Any] | None = None
    if audit_backend is not None:
        with tempfile.TemporaryDirectory(prefix="apiary-audit-") as tmp:
            extracted = Path(tmp) / "ext"
            _safe_extract(target_dir / tarball_filename, extracted)
            # npm tarballs nest under ``package/``
            inner = extracted / "package"
            if not (inner / "package.json").exists():
                # find any child holding package.json
                for child in extracted.iterdir():
                    if (child / "package.json").exists():
                        inner = child
                        break
            try:
                prompt = build_audit_prompt(inner)
                result = audit_backend.audit(prompt)
                audit_verdict = result.verdict
                audit_payload = asdict(result)
            except (OSError, RuntimeError, ValueError) as exc:
                logger.warning("audit failed for %s@%s: %s", package, version, exc)
                audit_payload = {
                    "verdict": "suspicious",
                    "confidence": 0.0,
                    "reasoning": f"backend error: {exc}",
                    "findings": [],
                }
                audit_verdict = "suspicious"

    sidecar = {
        "package": package,
        "version": version,
        "ts": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "verdict": decision.verdict,
            "failed_rules": decision.failed_rules,
            "passed_rules": decision.passed_rules,
            "evidence": decision.evidence,
        },
        "audit": audit_payload,
    }
    (target_dir / ".audit.json").write_text(
        json.dumps(sidecar, indent=2), encoding="utf-8"
    )
    return SeedResult(
        package=package,
        version=version,
        verdict=decision.verdict,
        audit_verdict=audit_verdict,
        bytes=len(tarball_bytes),
    )


def seed_from_top_packages(
    count: int = 2000,
    audit_backend: AuditBackend | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    workers: int = 8,
    min_age_days: int = 14,
    max_size_mb: int = 5,
) -> dict[str, str]:
    """Seed the cache with the top-N most-popular packages."""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    names = _query_top_packages(count=count)
    quarantine_db = load_quarantine_db()
    results: dict[str, str] = {}

    with httpx.Client(timeout=60.0) as client:
        def _one(name: str) -> SeedResult:
            try:
                metadata = _fetch_metadata(client, name)
                version = _latest_version(metadata)
                if not version:
                    return SeedResult(name, "", "skipped", None, 0, "no version")
                tarball, filename = _fetch_tarball(client, metadata, version)
                if len(tarball) > max_size_mb * 1024 * 1024:
                    return SeedResult(
                        name, version, "skipped", None, len(tarball), "too large"
                    )
                return _audit_one(
                    name,
                    version,
                    metadata,
                    tarball,
                    filename,
                    cache_dir,
                    quarantine_db,
                    audit_backend,
                    min_age_days,
                )
            except (httpx.HTTPError, RuntimeError, OSError) as exc:
                return SeedResult(name, "", "error", None, 0, str(exc))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_one, name): name for name in names}
            for fut in as_completed(futures):
                res = fut.result()
                key = f"{res.package}@{res.version}" if res.version else res.package
                results[key] = res.verdict
                logger.info(
                    "%s -> %s (audit=%s, %dB)%s",
                    key,
                    res.verdict,
                    res.audit_verdict,
                    res.bytes,
                    f" err={res.error}" if res.error else "",
                )
    return results


def seed_from_list(
    package_list_file: Path,
    audit_backend: AuditBackend | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    workers: int = 4,
    min_age_days: int = 14,
    max_size_mb: int = 5,
) -> dict[str, str]:
    """Seed every ``pkg@version`` line in ``package_list_file``."""
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    quarantine_db = load_quarantine_db()
    items: list[tuple[str, str]] = []
    for raw in Path(package_list_file).read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        if "@" not in raw:
            logger.warning("skipping malformed line: %s", raw)
            continue
        if raw.startswith("@"):
            # scoped: split on the LAST @ so @scope/name@version parses cleanly
            at_idx = raw.rfind("@")
            pkg, ver = raw[:at_idx], raw[at_idx + 1:]
        else:
            pkg, ver = raw.split("@", 1)
        items.append((pkg.strip(), ver.strip()))

    results: dict[str, str] = {}
    with httpx.Client(timeout=60.0) as client:
        def _one(pair: tuple[str, str]) -> SeedResult:
            pkg, ver = pair
            try:
                metadata = _fetch_metadata(client, pkg)
                if ver not in (metadata.get("versions") or {}):
                    return SeedResult(pkg, ver, "skipped", None, 0, "version absent")
                tarball, filename = _fetch_tarball(client, metadata, ver)
                if len(tarball) > max_size_mb * 1024 * 1024:
                    return SeedResult(
                        pkg, ver, "skipped", None, len(tarball), "too large"
                    )
                return _audit_one(
                    pkg,
                    ver,
                    metadata,
                    tarball,
                    filename,
                    cache_dir,
                    quarantine_db,
                    audit_backend,
                    min_age_days,
                )
            except (httpx.HTTPError, RuntimeError, OSError) as exc:
                return SeedResult(pkg, ver, "error", None, 0, str(exc))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_one, pair): pair for pair in items}
            for fut in as_completed(futures):
                res = fut.result()
                results[f"{res.package}@{res.version}"] = res.verdict
                logger.info(
                    "%s@%s -> %s%s",
                    res.package,
                    res.version,
                    res.verdict,
                    f" err={res.error}" if res.error else "",
                )
    return results


def _build_backend(name: str | None, **kwargs: Any) -> AuditBackend | None:
    if not name or name == "none":
        return None
    return get_backend(name, **kwargs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apiary-cache-seed")
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--from-file", type=Path, default=None)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--min-age-days", type=int, default=14)
    parser.add_argument("--max-size-mb", type=int, default=5)
    parser.add_argument(
        "--audit-backend",
        default="none",
        choices=("none", "openai", "ollama", "dwarfstar"),
    )
    parser.add_argument("--audit-model", default=None)
    parser.add_argument("--audit-base-url", default=None)
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    backend_kwargs: dict[str, Any] = {}
    if args.audit_model:
        backend_kwargs["model"] = args.audit_model
    if args.audit_base_url:
        backend_kwargs["base_url"] = args.audit_base_url
    backend = _build_backend(args.audit_backend, **backend_kwargs)

    if args.from_file:
        results = seed_from_list(
            args.from_file,
            audit_backend=backend,
            cache_dir=args.cache_dir,
            workers=args.workers,
            min_age_days=args.min_age_days,
            max_size_mb=args.max_size_mb,
        )
    else:
        results = seed_from_top_packages(
            count=args.count,
            audit_backend=backend,
            cache_dir=args.cache_dir,
            workers=args.workers,
            min_age_days=args.min_age_days,
            max_size_mb=args.max_size_mb,
        )

    summary: dict[str, int] = {}
    for verdict in results.values():
        summary[verdict] = summary.get(verdict, 0) + 1
    print(json.dumps({"total": len(results), "by_verdict": summary}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())


# silence "shutil unused" if user has slimmer deps
_ = shutil
