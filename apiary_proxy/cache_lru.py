"""Filesystem-backed LRU eviction for the proxy tarball cache.

The proxy stores every served tarball under ``data/proxy-cache``. Left
unchecked this grows without bound; popular packages alone reach gigabytes
inside a week. This module provides a simple LRU eviction sweep:

* "Recency" is the file mtime. Reads ``touch`` the file so that recently
  consumed tarballs survive longer.
* When the cache size exceeds ``max_bytes``, eviction removes oldest mtimes
  until the total drops to ``target_bytes`` (default: 80% of ``max_bytes``).
* A sidecar ``.cache-stats.json`` is written after every sweep so operators
  can see the most recent eviction count and total size without scanning
  the tree themselves.

Only ``.tgz`` files participate in the size accounting and eviction. The
``metadata.json`` and ``.audit.json`` sidecars are intentionally preserved
because they are small, cheap to regenerate, and useful for forensics.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("apiary.proxy.cache_lru")

DEFAULT_MAX_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB
DEFAULT_TARGET_RATIO = 0.8
DEFAULT_SWEEP_INTERVAL_SECONDS = 300.0  # 5 min
DEFAULT_STATS_FILENAME = ".cache-stats.json"
EVICTABLE_SUFFIXES: frozenset[str] = frozenset({".tgz"})


@dataclass
class CacheStats:
    """Snapshot of cache health after a sweep."""

    total_bytes: int = 0
    file_count: int = 0
    last_sweep_ts: float = 0.0
    last_evicted_files: int = 0
    last_evicted_bytes: int = 0

    def to_dict(self) -> dict:
        return {
            "total_bytes": self.total_bytes,
            "file_count": self.file_count,
            "last_sweep_ts": self.last_sweep_ts,
            "last_evicted_files": self.last_evicted_files,
            "last_evicted_bytes": self.last_evicted_bytes,
        }


@dataclass
class LRUCacheEvictor:
    """Periodic LRU eviction for the proxy cache tree."""

    cache_dir: Path
    max_bytes: int = DEFAULT_MAX_BYTES
    target_ratio: float = DEFAULT_TARGET_RATIO
    sweep_interval_seconds: float = DEFAULT_SWEEP_INTERVAL_SECONDS
    stats_filename: str = DEFAULT_STATS_FILENAME
    stats: CacheStats = field(default_factory=CacheStats)
    _task: Optional[asyncio.Task] = field(default=None, init=False, repr=False)
    _stop_event: Optional[asyncio.Event] = field(default=None, init=False, repr=False)

    @property
    def target_bytes(self) -> int:
        return int(self.max_bytes * self.target_ratio)

    # ---- public ops ------------------------------------------------------

    def touch(self, path: Path) -> None:
        """Update file mtime so that this file is treated as recently used."""
        try:
            if path.exists():
                now = time.time()
                # ``os.utime`` is the cross-platform way to set (atime, mtime).
                import os

                os.utime(path, (now, now))
        except OSError as exc:
            logger.debug("touch failed for %s: %s", path, exc)

    def list_evictable(self) -> list[tuple[Path, int, float]]:
        """Return ``(path, size, mtime)`` for every evictable file."""
        out: list[tuple[Path, int, float]] = []
        if not self.cache_dir.exists():
            return out
        for path in self.cache_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix not in EVICTABLE_SUFFIXES:
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            out.append((path, st.st_size, st.st_mtime))
        return out

    def current_total_bytes(self) -> int:
        return sum(size for _path, size, _mtime in self.list_evictable())

    def sweep_once(self) -> CacheStats:
        """Run one eviction pass. Safe to call from any thread."""
        entries = self.list_evictable()
        total = sum(size for _p, size, _m in entries)
        file_count = len(entries)
        evicted_files = 0
        evicted_bytes = 0

        if total > self.max_bytes:
            # Oldest first.
            entries.sort(key=lambda item: item[2])
            target = self.target_bytes
            for path, size, _mtime in entries:
                if total <= target:
                    break
                try:
                    path.unlink()
                    total -= size
                    file_count -= 1
                    evicted_files += 1
                    evicted_bytes += size
                except OSError as exc:
                    logger.warning("could not evict %s: %s", path, exc)
            if evicted_files:
                logger.info(
                    "lru-evict: removed %d files (%d bytes); now %d bytes",
                    evicted_files, evicted_bytes, total,
                )

        self.stats = CacheStats(
            total_bytes=total,
            file_count=file_count,
            last_sweep_ts=time.time(),
            last_evicted_files=evicted_files,
            last_evicted_bytes=evicted_bytes,
        )
        self._write_stats()
        return self.stats

    def _write_stats(self) -> None:
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            stats_path = self.cache_dir / self.stats_filename
            tmp = stats_path.with_suffix(stats_path.suffix + ".tmp")
            tmp.write_text(
                json.dumps(self.stats.to_dict(), indent=2), encoding="utf-8"
            )
            tmp.replace(stats_path)
        except OSError as exc:
            logger.warning("could not write cache stats: %s", exc)

    # ---- asyncio integration ---------------------------------------------

    async def _run_loop(self) -> None:
        assert self._stop_event is not None
        while not self._stop_event.is_set():
            try:
                await asyncio.to_thread(self.sweep_once)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("lru sweep crashed: %s", exc)
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self.sweep_interval_seconds,
                )
            except asyncio.TimeoutError:
                continue

    def start(self) -> None:
        """Spawn the background sweep task. No-op if already running."""
        if self._task is not None and not self._task.done():
            return
        self._stop_event = asyncio.Event()
        loop = asyncio.get_event_loop()
        self._task = loop.create_task(self._run_loop(), name="apiary-lru-evictor")
        logger.info(
            "lru evictor started; cache_dir=%s max_bytes=%d interval=%.1fs",
            self.cache_dir, self.max_bytes, self.sweep_interval_seconds,
        )

    async def stop(self) -> None:
        """Signal the background task and wait for it to exit."""
        if self._stop_event is not None:
            self._stop_event.set()
        if self._task is not None:
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("lru evictor stopped")
