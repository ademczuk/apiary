"""Tests for the LRU cache evictor."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from apiary_proxy.cache_lru import LRUCacheEvictor


def _write_tarball(path: Path, payload: bytes, mtime: float | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def test_sweep_evicts_oldest_when_over_threshold(tmp_path: Path) -> None:
    cache = tmp_path / "proxy-cache"
    evictor = LRUCacheEvictor(
        cache_dir=cache,
        max_bytes=300,
        target_ratio=0.5,  # target 150
    )

    now = time.time()
    _write_tarball(cache / "a-1.0.0.tgz", b"a" * 100, mtime=now - 300)
    _write_tarball(cache / "b-1.0.0.tgz", b"b" * 100, mtime=now - 200)
    _write_tarball(cache / "c-1.0.0.tgz", b"c" * 100, mtime=now - 100)
    _write_tarball(cache / "d-1.0.0.tgz", b"d" * 100, mtime=now - 50)

    stats = evictor.sweep_once()

    # Total starts at 400; max is 300; target is 150. Should evict until
    # <=150, removing 3 oldest files.
    remaining = sorted(p.name for p in cache.glob("*.tgz"))
    assert remaining == ["d-1.0.0.tgz"]
    assert stats.last_evicted_files == 3
    assert stats.last_evicted_bytes == 300
    assert stats.total_bytes == 100


def test_sweep_noop_when_under_threshold(tmp_path: Path) -> None:
    cache = tmp_path / "proxy-cache"
    evictor = LRUCacheEvictor(cache_dir=cache, max_bytes=10_000)
    _write_tarball(cache / "x-1.0.0.tgz", b"x" * 100)
    stats = evictor.sweep_once()
    assert stats.last_evicted_files == 0
    assert (cache / "x-1.0.0.tgz").exists()


def test_touch_updates_mtime(tmp_path: Path) -> None:
    cache = tmp_path / "proxy-cache"
    evictor = LRUCacheEvictor(cache_dir=cache, max_bytes=300, target_ratio=0.5)
    now = time.time()
    _write_tarball(cache / "old.tgz", b"a" * 100, mtime=now - 300)
    _write_tarball(cache / "new.tgz", b"b" * 100, mtime=now - 200)
    _write_tarball(cache / "newer.tgz", b"c" * 100, mtime=now - 100)
    _write_tarball(cache / "newest.tgz", b"d" * 100, mtime=now - 50)

    # Touch the oldest so it survives.
    evictor.touch(cache / "old.tgz")
    evictor.sweep_once()

    remaining = sorted(p.name for p in cache.glob("*.tgz"))
    assert "old.tgz" in remaining
    assert "new.tgz" not in remaining


def test_only_tgz_files_are_evictable(tmp_path: Path) -> None:
    cache = tmp_path / "proxy-cache"
    evictor = LRUCacheEvictor(cache_dir=cache, max_bytes=100, target_ratio=0.5)
    _write_tarball(cache / "a.tgz", b"a" * 200)
    metadata = cache / "metadata.json"
    metadata.parent.mkdir(parents=True, exist_ok=True)
    metadata.write_text("{}", encoding="utf-8")
    evictor.sweep_once()
    # metadata.json must survive.
    assert metadata.exists()


def test_stats_sidecar_written(tmp_path: Path) -> None:
    cache = tmp_path / "proxy-cache"
    evictor = LRUCacheEvictor(cache_dir=cache, max_bytes=1024)
    _write_tarball(cache / "x.tgz", b"x" * 100)
    evictor.sweep_once()
    sidecar = cache / ".cache-stats.json"
    assert sidecar.exists()
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    assert data["total_bytes"] == 100
    assert data["file_count"] == 1


def test_target_bytes_property(tmp_path: Path) -> None:
    evictor = LRUCacheEvictor(
        cache_dir=tmp_path, max_bytes=1000, target_ratio=0.8
    )
    assert evictor.target_bytes == 800


@pytest.mark.asyncio
async def test_start_and_stop_lifecycle(tmp_path: Path) -> None:
    pytest.importorskip("pytest_asyncio")
    cache = tmp_path / "proxy-cache"
    evictor = LRUCacheEvictor(
        cache_dir=cache, max_bytes=1024, sweep_interval_seconds=0.05
    )
    evictor.start()
    import asyncio

    await asyncio.sleep(0.2)
    await evictor.stop()
    assert (cache / ".cache-stats.json").exists()
