"""Composer (Packagist) Registry implementation.

Composer's package index lives at Packagist. The v2 metadata API returns a
JSON document containing every released version, including ``dist``
(archive URL + sha1) and ``source`` (VCS pointer). Composer's lifecycle
hooks live in ``composer.json`` under ``scripts``: ``pre-install-cmd``,
``post-install-cmd``, ``pre-update-cmd``, ``post-update-cmd``,
``post-autoload-dump``, plus user-defined scripts.

Wire format:

- Metadata: ``GET https://repo.packagist.org/p2/{vendor}/{package}.json``
  returns ``packages[<vendor>/<package>]`` as a list of version blocks.
- Dist archive: ``GET <packages[*].dist.url>`` returns a zip from a
  GitHub / GitLab / Bitbucket archive endpoint.

Integrity:
    Composer's ``dist.shasum`` is a sha1 hex digest of the zip archive.
    sha1 is weaker than what we would prefer; the policy engine treats a
    matching sha1 as a low-confidence signal but still surfaces a
    mismatch as a clear block.

Repository:
    ``source.url`` carries the VCS pointer directly. When absent we fall
    back to ``homepage``. Most Packagist packages publish at least one of
    the two.

Install scripts:
    Composer scripts are arbitrary shell commands or PHP callbacks
    bound to lifecycle events. We surface them verbatim and let the
    policy engine apply its lifecycle-script rule. Trivial scripts
    (e.g. ``@php artisan optimize``) pass; non-trivial commands fail.

Name normalization:
    Composer keeps ``vendor/package`` exactly as published. Casing is
    case-insensitive in resolution but the canonical form is lowercase.
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

logger = logging.getLogger("apiary.registry.composer")

DEFAULT_COMPOSER_UPSTREAM = "https://repo.packagist.org"


class ComposerRegistry(Registry):
    """Concrete Registry talking to Packagist's v2 metadata API."""

    ecosystem = "composer"

    def __init__(
        self,
        client: httpx.AsyncClient,
        upstream: str = DEFAULT_COMPOSER_UPSTREAM,
    ) -> None:
        self.client = client
        self._upstream = upstream.rstrip("/")

    def upstream_url(self) -> str:
        return self._upstream

    def normalize_package_name(self, name: str) -> str:
        # Packagist resolves names case-insensitively but canonical form
        # is lowercase ``vendor/package``.
        return name.strip().lower()

    async def get_metadata(self, package: str, version: str) -> PackageMetadata:
        canonical = self.normalize_package_name(package)
        if "/" not in canonical:
            raise PackageNotFoundError(
                f"composer names must be 'vendor/package': got {package!r}"
            )
        encoded = quote(canonical, safe="/")
        url = f"{self._upstream}/p2/{encoded}.json"
        try:
            resp = await self.client.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise UpstreamError(f"composer upstream error: {exc}") from exc
        if resp.status_code == 404:
            raise PackageNotFoundError(f"composer package not found: {package}")
        if resp.status_code >= 400:
            raise UpstreamError(
                f"composer upstream {resp.status_code} for {package}"
            )
        try:
            payload = resp.json()
        except json.JSONDecodeError as exc:
            raise UpstreamError(f"composer upstream non-json: {exc}") from exc

        return self._project(canonical, version, payload)

    def _project(
        self, package: str, version: str, payload: dict[str, Any]
    ) -> PackageMetadata:
        packages = payload.get("packages") or {}
        if not isinstance(packages, dict):
            raise UpstreamError("composer 'packages' is not an object")

        version_blocks = packages.get(package)
        if not isinstance(version_blocks, list):
            raise PackageNotFoundError(
                f"composer package list missing for {package}"
            )

        match: dict[str, Any] | None = None
        for block in version_blocks:
            if not isinstance(block, dict):
                continue
            if block.get("version") == version or block.get("version_normalized") == version:
                match = block
                break

        if match is None:
            raise PackageNotFoundError(
                f"composer version {version!r} missing for {package}"
            )

        # Composer ships ISO-8601 timestamps under 'time'.
        release_time = match.get("time") if isinstance(match.get("time"), str) else None

        dist = match.get("dist") or {}
        if not isinstance(dist, dict):
            dist = {}
        tarball_url = dist.get("url") if isinstance(dist.get("url"), str) else ""
        integrity_hash = dist.get("shasum") if isinstance(dist.get("shasum"), str) else None
        if integrity_hash:
            integrity_hash = integrity_hash.lower()

        source = match.get("source") or {}
        repository_url: str | None = None
        if isinstance(source, dict):
            src_url = source.get("url")
            if isinstance(src_url, str):
                repository_url = src_url
        if repository_url is None:
            homepage = match.get("homepage")
            if isinstance(homepage, str):
                repository_url = homepage

        scripts_raw = match.get("scripts") or {}
        scripts: dict[str, str] = {}
        if isinstance(scripts_raw, dict):
            for hook, cmd in scripts_raw.items():
                if not isinstance(hook, str):
                    continue
                if isinstance(cmd, str):
                    scripts[hook] = cmd
                elif isinstance(cmd, list):
                    # Composer permits an array of commands per hook; join
                    # them so the lifecycle-script rule sees a single
                    # multi-line invocation.
                    flat = [c for c in cmd if isinstance(c, str)]
                    if flat:
                        scripts[hook] = " && ".join(flat)

        return PackageMetadata(
            name=package,
            version=version,
            ecosystem="composer",
            release_time=release_time,
            install_scripts=scripts,
            integrity_hash=integrity_hash,
            integrity_algo="sha1",
            repository_url=repository_url,
            tarball_url=tarball_url or "",
            raw=match,
        )

    async def get_tarball(self, package: str, version: str) -> bytes:
        meta = await self.get_metadata(package, version)
        if not meta.tarball_url:
            raise UpstreamError(f"no dist URL for {package}@{version}")
        try:
            resp = await self.client.get(meta.tarball_url)
        except httpx.HTTPError as exc:
            raise UpstreamError(f"composer dist fetch error: {exc}") from exc
        if resp.status_code == 404:
            raise PackageNotFoundError(
                f"composer dist missing for {package}@{version}"
            )
        if resp.status_code >= 400:
            raise UpstreamError(
                f"composer dist upstream {resp.status_code} for {package}@{version}"
            )
        return resp.content


__all__ = ["ComposerRegistry", "DEFAULT_COMPOSER_UPSTREAM"]
