"""npm Registry implementation.

Lifts the npm-specific HTTP wiring out of the original proxy and into a
concrete Registry. The proxy keeps its own request-routing layer, on-disk
cache, and policy bridge; this module owns the wire protocol.

Wire format:

- Metadata: ``GET https://registry.npmjs.org/{package}`` returns a JSON
  document with ``time[ver]``, ``versions[ver].dist.{tarball,integrity}``,
  ``versions[ver].scripts``, and ``versions[ver].repository``.
- Tarball: ``GET https://registry.npmjs.org/{package}/-/{file}.tgz``
  returns a gzipped tar archive.

Integrity:
    npm registry emits SRI (``sha512-<base64>``) by default. Older metadata
    can carry sha384 or sha256. The Registry preserves the SRI string in
    ``integrity_hash`` and stamps the algo separately for the policy
    engine.

Repository:
    ``versions[ver].repository.url`` (or the bare string form) is the
    canonical source-of-truth. The npm registry mirrors ``gitHead`` per
    version so the source-match rule has a commit pin.

Scopes:
    npm scoped packages keep their ``@`` prefix and forward slash. URLs
    encode the slash as ``%2F``; we use httpx's path quoting.
"""

from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import quote

import httpx

from apiary_proxy.registry import (
    PackageMetadata,
    PackageNotFoundError,
    Registry,
    UpstreamError,
)

logger = logging.getLogger("apiary.registry.npm")

DEFAULT_NPM_UPSTREAM = "https://registry.npmjs.org"


def _algo_from_integrity(integrity: str | None) -> str:
    """Pick the strongest algo present in an SRI string."""
    if not integrity:
        return "sha512"
    ranking = {"sha512": 3, "sha384": 2, "sha256": 1}
    best = "sha512"
    best_rank = -1
    for alt in integrity.strip().split():
        algo, _, _digest = alt.partition("-")
        algo_lower = algo.lower()
        rank = ranking.get(algo_lower, -1)
        if rank > best_rank:
            best = algo_lower
            best_rank = rank
    return best


class NpmRegistry(Registry):
    """Concrete Registry talking to a v1 npm registry endpoint."""

    ecosystem = "npm"

    def __init__(
        self,
        client: httpx.AsyncClient,
        upstream: str = DEFAULT_NPM_UPSTREAM,
    ) -> None:
        self.client = client
        self._upstream = upstream.rstrip("/")

    def upstream_url(self) -> str:
        return self._upstream

    def normalize_package_name(self, name: str) -> str:
        # npm package names are case-preserving and may carry a scope prefix.
        return name.strip()

    async def get_metadata(self, package: str, version: str) -> PackageMetadata:
        raw = await self._fetch_raw_metadata(package)
        return self._project(package, version, raw)

    async def _fetch_raw_metadata(self, package: str) -> dict[str, Any]:
        # npm scoped names contain a slash that must not be double-encoded.
        encoded = quote(package, safe="@/")
        url = f"{self._upstream}/{encoded}"
        try:
            resp = await self.client.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise UpstreamError(f"npm upstream error: {exc}") from exc
        if resp.status_code == 404:
            raise PackageNotFoundError(f"npm package not found: {package}")
        if resp.status_code >= 400:
            raise UpstreamError(f"npm upstream {resp.status_code} for {package}")
        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            raise UpstreamError(f"npm upstream non-json: {exc}") from exc

    def _project(
        self, package: str, version: str, raw: dict[str, Any]
    ) -> PackageMetadata:
        versions = raw.get("versions") or {}
        if version not in versions:
            raise PackageNotFoundError(
                f"version {version!r} missing from npm metadata for {package}"
            )

        block = versions[version]
        if not isinstance(block, dict):
            raise UpstreamError(f"npm versions[{version}] is not an object")

        time_map = raw.get("time") or {}
        release_time = time_map.get(version) if isinstance(time_map, dict) else None

        scripts_raw = block.get("scripts") or {}
        scripts: dict[str, str] = {}
        if isinstance(scripts_raw, dict):
            for hook, cmd in scripts_raw.items():
                if isinstance(hook, str) and isinstance(cmd, str):
                    scripts[hook] = cmd

        dist = block.get("dist") or {}
        if not isinstance(dist, dict):
            dist = {}
        integrity = dist.get("integrity") if isinstance(dist.get("integrity"), str) else None
        tarball_url = dist.get("tarball") if isinstance(dist.get("tarball"), str) else ""

        repository = block.get("repository")
        repository_url: str | None = None
        if isinstance(repository, dict):
            url = repository.get("url")
            if isinstance(url, str):
                repository_url = url
        elif isinstance(repository, str):
            repository_url = repository

        return PackageMetadata(
            name=package,
            version=version,
            ecosystem="npm",
            release_time=release_time,
            install_scripts=scripts,
            # npm integrity is already SRI base64; keep it native so the
            # checksum rule can be reused unchanged on npm packages.
            integrity_hash=integrity,
            integrity_algo=_algo_from_integrity(integrity),
            repository_url=repository_url,
            tarball_url=tarball_url or "",
            raw=raw,
        )

    async def get_tarball(self, package: str, version: str) -> bytes:
        # The original proxy passes filename explicitly via URL pattern. To
        # keep the Registry interface symmetric across ecosystems, look up
        # the tarball URL via metadata and fetch it directly.
        raw = await self._fetch_raw_metadata(package)
        meta = self._project(package, version, raw)
        if not meta.tarball_url:
            raise UpstreamError(f"no tarball URL for {package}@{version}")
        try:
            resp = await self.client.get(meta.tarball_url)
        except httpx.HTTPError as exc:
            raise UpstreamError(f"npm tarball fetch error: {exc}") from exc
        if resp.status_code == 404:
            raise PackageNotFoundError(
                f"npm tarball missing for {package}@{version}"
            )
        if resp.status_code >= 400:
            raise UpstreamError(
                f"npm tarball upstream {resp.status_code} for {package}@{version}"
            )
        return resp.content


__all__ = ["NpmRegistry", "DEFAULT_NPM_UPSTREAM"]
