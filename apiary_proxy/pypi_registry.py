"""PyPI Registry implementation.

PyPI does not ship explicit install scripts the way npm does. The equivalent
of npm's lifecycle hooks is the source distribution's build-time code:
``setup.py`` runs whatever it likes when pip installs an sdist, and the
``setup.cfg`` or ``pyproject.toml`` can declare custom build commands. v1
treats every non-trivial setup.py as a candidate install-script hook so the
policy engine can apply the same rule against it.

Wire format:

- Metadata: ``GET https://pypi.org/pypi/{package}/{version}/json`` returns
  the PEP 691 JSON API with ``info``, ``urls``, ``last_serial``.
- Dist archive: ``GET <info.url>`` (or pick from ``urls`` for the wheel /
  sdist preferred by the policy).

Integrity:
    PyPI publishes ``info.digests.sha256`` (and md5_digest legacy) as
    lowercase hex strings. We canonicalize to sha256 hex.

Repository:
    PyPI is loose about source URLs. We look at ``info.project_urls`` with
    the keys "Repository", "Source", "Source Code", and "Homepage", in
    that order. Many packages publish none of these, so the source-match
    rule is opportunistic.

Name normalization (PEP 503):
    Names are lowercased and runs of ``-_.`` collapse to a single ``-``.
    PyPI treats Flask, FLASK, and flask as the same project; we do too.

Install-script equivalent:
    For wheels (the recommended distribution format) we surface no
    install scripts: wheels MUST NOT execute code at install time. For
    sdists we cannot fetch and exec ``setup.py`` without running it, so
    we look at the metadata's ``description`` and ``project_urls`` for
    "post-install" hints, and we flag any sdist-only distribution as a
    candidate for closer review.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx

from apiary_proxy.registry import (
    PackageMetadata,
    PackageNotFoundError,
    Registry,
    UpstreamError,
)

logger = logging.getLogger("apiary.registry.pypi")

DEFAULT_PYPI_UPSTREAM = "https://pypi.org"

# Project-URL keys that historically point at the source repository, in
# preference order. PyPI is loose about this so we walk multiple aliases.
_REPO_URL_KEYS: tuple[str, ...] = (
    "Repository",
    "Source",
    "Source Code",
    "Source-Code",
    "source",
    "Code",
    "GitHub",
    "Homepage",
)

# Heuristic indicators of non-trivial setup.py behavior, surfaced as
# synthetic lifecycle-hook entries so the policy engine's install_scripts
# rule fires. These map description-level hints rather than executing
# arbitrary code (which would defeat the whole supply-chain gate).
_SETUP_PY_HINTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("install_requires_url", re.compile(r"install_requires.*http[s]?://", re.I)),
    ("custom_install_cmd", re.compile(r"cmdclass\s*=\s*\{", re.I)),
    ("post_install_hook", re.compile(r"post[_\- ]install", re.I)),
)


def _canonicalize(name: str) -> str:
    """Implement PEP 503 normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


class PyPIRegistry(Registry):
    """Concrete Registry talking to PyPI's JSON API."""

    ecosystem = "pypi"

    def __init__(
        self,
        client: httpx.AsyncClient,
        upstream: str = DEFAULT_PYPI_UPSTREAM,
    ) -> None:
        self.client = client
        self._upstream = upstream.rstrip("/")

    def upstream_url(self) -> str:
        return self._upstream

    def normalize_package_name(self, name: str) -> str:
        return _canonicalize(name.strip())

    async def get_metadata(self, package: str, version: str) -> PackageMetadata:
        canonical = self.normalize_package_name(package)
        url = f"{self._upstream}/pypi/{canonical}/{version}/json"
        try:
            resp = await self.client.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise UpstreamError(f"pypi upstream error: {exc}") from exc
        if resp.status_code == 404:
            raise PackageNotFoundError(f"pypi package not found: {package}@{version}")
        if resp.status_code >= 400:
            raise UpstreamError(
                f"pypi upstream {resp.status_code} for {package}@{version}"
            )
        try:
            payload = resp.json()
        except json.JSONDecodeError as exc:
            raise UpstreamError(f"pypi upstream non-json: {exc}") from exc
        return self._project(canonical, version, payload)

    def _project(
        self, package: str, version: str, payload: dict[str, Any]
    ) -> PackageMetadata:
        info = payload.get("info") or {}
        urls = payload.get("urls") or []
        if not isinstance(info, dict):
            info = {}
        if not isinstance(urls, list):
            urls = []

        # Pick the preferred distribution. Wheel > sdist for safety; the
        # policy engine still inspects setup.py-style hints separately.
        preferred = _pick_distribution(urls)
        tarball_url = ""
        integrity_hash: str | None = None
        release_time: str | None = None

        if preferred is not None:
            tarball_url = preferred.get("url") or ""
            digests = preferred.get("digests") or {}
            if isinstance(digests, dict):
                sha256 = digests.get("sha256")
                if isinstance(sha256, str):
                    integrity_hash = sha256.lower()
            upload_time_iso = preferred.get("upload_time_iso_8601")
            if isinstance(upload_time_iso, str):
                release_time = upload_time_iso
            elif isinstance(preferred.get("upload_time"), str):
                release_time = preferred["upload_time"]

        # Fallback: ``info.upload_time`` (rare; not all PyPI versions set it).
        if release_time is None:
            info_time = info.get("upload_time")
            if isinstance(info_time, str):
                release_time = info_time

        repository_url = _pick_repository_url(info)

        # Synthesize install-script hooks from heuristics.
        scripts = _detect_install_hooks(info, preferred)

        return PackageMetadata(
            name=package,
            version=version,
            ecosystem="pypi",
            release_time=release_time,
            install_scripts=scripts,
            integrity_hash=integrity_hash,
            integrity_algo="sha256",
            repository_url=repository_url,
            tarball_url=tarball_url,
            raw=payload,
        )

    async def get_tarball(self, package: str, version: str) -> bytes:
        meta = await self.get_metadata(package, version)
        if not meta.tarball_url:
            raise UpstreamError(f"no dist URL for {package}@{version}")
        try:
            resp = await self.client.get(meta.tarball_url)
        except httpx.HTTPError as exc:
            raise UpstreamError(f"pypi dist fetch error: {exc}") from exc
        if resp.status_code == 404:
            raise PackageNotFoundError(
                f"pypi dist missing for {package}@{version}"
            )
        if resp.status_code >= 400:
            raise UpstreamError(
                f"pypi dist upstream {resp.status_code} for {package}@{version}"
            )
        return resp.content


def _pick_distribution(urls: list[Any]) -> dict[str, Any] | None:
    """Choose the preferred dist: wheel first, then sdist, then anything."""
    wheels: list[dict[str, Any]] = []
    sdists: list[dict[str, Any]] = []
    others: list[dict[str, Any]] = []
    for entry in urls:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("packagetype")
        if kind == "bdist_wheel":
            wheels.append(entry)
        elif kind == "sdist":
            sdists.append(entry)
        else:
            others.append(entry)
    if wheels:
        return wheels[0]
    if sdists:
        return sdists[0]
    if others:
        return others[0]
    return None


def _pick_repository_url(info: dict[str, Any]) -> str | None:
    """Pull a repository URL out of project_urls, falling back to home_page."""
    project_urls = info.get("project_urls") or {}
    if isinstance(project_urls, dict):
        for key in _REPO_URL_KEYS:
            value = project_urls.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    home_page = info.get("home_page")
    if isinstance(home_page, str) and home_page.strip():
        return home_page.strip()
    return None


def _detect_install_hooks(
    info: dict[str, Any], preferred: dict[str, Any] | None
) -> dict[str, str]:
    """Heuristic surface for PyPI's setup.py-equivalent install scripts.

    Wheel-only distributions surface no scripts (the format forbids code at
    install time). sdist-only distributions surface a synthetic
    ``setup_py`` hook so the policy engine's install-script rule can fire.
    Description-level hints surface as additional named hooks so a memo
    reader can see which signal tripped the rule.
    """
    scripts: dict[str, str] = {}
    if preferred is None:
        return scripts

    kind = preferred.get("packagetype")
    filename = preferred.get("filename", "")

    if kind == "sdist" or filename.endswith((".tar.gz", ".zip")):
        # The mere presence of an sdist means setup.py / pyproject.toml
        # build-system code will execute. We treat this as a non-trivial
        # install command so the policy engine reviews it.
        scripts["setup_py"] = "python setup.py install"

    # Walk the description for heuristic markers. We only mark the hook;
    # we never execute the description.
    description = info.get("description") or ""
    if not isinstance(description, str):
        description = ""
    for hook_name, pattern in _SETUP_PY_HINTS:
        if pattern.search(description):
            scripts[hook_name] = f"<sdist hint: {hook_name}>"

    return scripts


__all__ = ["PyPIRegistry", "DEFAULT_PYPI_UPSTREAM"]
