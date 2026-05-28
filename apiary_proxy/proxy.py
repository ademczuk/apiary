"""FastAPI npm registry proxy with policy gating and on-disk tarball cache.

Implements the subset of the npm registry HTTP API that npm, pnpm, and yarn
need to install a package:

    GET  /{package}                         metadata for an unscoped package
    GET  /@{scope}/{name}                   metadata for a scoped package
    GET  /{package}/-/{filename}.tgz        tarball download (cached + gated)
    GET  /@{scope}/{name}/-/{filename}.tgz  scoped tarball download
    POST /-/v1/login                        accept-anything stub (read-only)
    GET  /-/ping                            liveness for npm clients
    GET  /healthz                           operator health check
    GET  /audit                             tail of recent decisions

Cache layout::

    data/proxy-cache/
        <package>/
            metadata.json
            <version>/
                <filename>.tgz
                .audit.json   (optional, written by apiary_cache.seed)

Every request appends one line to ``data/proxy-audit.jsonl``.

CLI::

    python -m apiary_proxy.proxy --port 4873 \\
        --cache-dir data/proxy-cache \\
        --upstream https://registry.npmjs.org
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from apiary_policy import PolicyDecision, decide_policy, load_environment_policy
from apiary_proxy.cache_lru import LRUCacheEvictor
from apiary_proxy.composer_registry import ComposerRegistry, DEFAULT_COMPOSER_UPSTREAM
from apiary_proxy.npm_registry import NpmRegistry
from apiary_proxy.pypi_registry import PyPIRegistry, DEFAULT_PYPI_UPSTREAM
from apiary_proxy.registry import (
    PackageNotFoundError,
    Registry,
    UpstreamError,
    metadata_to_npm_shape,
)
from apiary_quarantine import load_quarantine_db

logger = logging.getLogger("apiary.proxy")

DEFAULT_UPSTREAM = "https://registry.npmjs.org"
DEFAULT_CACHE_DIR = Path("data/proxy-cache")
DEFAULT_AUDIT_LOG = Path("data/proxy-audit.jsonl")
DEFAULT_QUARANTINE_DIR = Path("quarantine")
METADATA_TTL_SECONDS = 3600  # 1h


@dataclass
class ProxyConfig:
    upstream: str = DEFAULT_UPSTREAM
    cache_dir: Path = DEFAULT_CACHE_DIR
    audit_log: Path = DEFAULT_AUDIT_LOG
    quarantine_dir: Path = DEFAULT_QUARANTINE_DIR
    metadata_ttl_seconds: int = METADATA_TTL_SECONDS
    min_age_days: int = 14
    public_base_url: str | None = None  # for dist.tarball rewriting
    environment: str = "preprod"
    env_config_path: Path | None = None
    source_cache_dir: Path = Path("data/source-cache")
    cache_max_bytes: int = 10 * 1024 * 1024 * 1024
    cache_sweep_seconds: float = 300.0
    # ecosystem selects which Registry the proxy mounts at startup. The
    # legacy npm routes stay registered for backwards-compatible behaviour;
    # the pypi / composer routes only fire when the matching ecosystem is
    # selected so that a proxy started in npm mode does not accidentally
    # serve unrelated indexes.
    ecosystem: str = "npm"

    def __post_init__(self) -> None:
        self.cache_dir = Path(self.cache_dir)
        self.audit_log = Path(self.audit_log)
        self.quarantine_dir = Path(self.quarantine_dir)
        self.source_cache_dir = Path(self.source_cache_dir)
        if self.env_config_path is not None:
            self.env_config_path = Path(self.env_config_path)
        self.upstream = self.upstream.rstrip("/")


@dataclass
class ProxyState:
    config: ProxyConfig = field(default_factory=ProxyConfig)
    client: httpx.AsyncClient | None = None
    quarantine_db: dict[str, Any] = field(default_factory=dict)
    evictor: LRUCacheEvictor | None = None
    registry: Registry | None = None

    async def aclose(self) -> None:
        if self.client is not None:
            await self.client.aclose()
            self.client = None
        if self.evictor is not None:
            await self.evictor.stop()
            self.evictor = None

    def reload_quarantine(self) -> None:
        try:
            self.quarantine_db = load_quarantine_db(self.config.quarantine_dir)
        except (OSError, ValueError) as exc:
            logger.warning("quarantine db load failed: %s", exc)
            self.quarantine_db = {}


state = ProxyState()


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------


def _audit(entry: dict[str, Any]) -> None:
    """Append one structured row to the audit log; never raise."""
    entry.setdefault("ts", datetime.now(timezone.utc).isoformat())
    try:
        state.config.audit_log.parent.mkdir(parents=True, exist_ok=True)
        with state.config.audit_log.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except OSError as exc:
        logger.warning("audit append failed: %s", exc)


def _package_cache_dir(package: str) -> Path:
    # scoped packages keep their slash in the cache path
    safe = package.replace("/", os.sep)
    return state.config.cache_dir / safe


def _metadata_path(package: str) -> Path:
    return _package_cache_dir(package) / "metadata.json"


def _tarball_path(package: str, version: str, filename: str) -> Path:
    return _package_cache_dir(package) / version / filename


def _audit_sidecar_path(package: str, version: str) -> Path:
    return _package_cache_dir(package) / version / ".audit.json"


def _rewrite_tarballs(metadata: dict[str, Any], base_url: str) -> dict[str, Any]:
    """Rewrite every ``dist.tarball`` URL to point at this proxy."""
    versions = metadata.get("versions") or {}
    if not isinstance(versions, dict):
        return metadata
    base = base_url.rstrip("/")
    for ver, block in versions.items():
        if not isinstance(block, dict):
            continue
        dist = block.get("dist") or {}
        if not isinstance(dist, dict):
            continue
        original = dist.get("tarball")
        if not original or not isinstance(original, str):
            continue
        # Original: https://registry.npmjs.org/<pkg>/-/<filename>.tgz
        marker = "/-/"
        idx = original.rfind(marker)
        if idx == -1:
            continue
        filename = original[idx + len(marker):]
        pkg_name = metadata.get("name", "")
        dist["tarball"] = f"{base}/{pkg_name}/-/{filename}"
        block["dist"] = dist
        versions[ver] = block
    metadata["versions"] = versions
    return metadata


def _public_base(req: Request) -> str:
    if state.config.public_base_url:
        return state.config.public_base_url
    return str(req.base_url).rstrip("/")


async def _fetch_upstream_metadata(package: str) -> dict[str, Any]:
    assert state.client is not None
    url = f"{state.config.upstream}/{package}"
    try:
        resp = await state.client.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"upstream error: {exc}") from exc
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail=f"package not found: {package}")
    if resp.status_code >= 400:
        raise HTTPException(
            status_code=502, detail=f"upstream {resp.status_code} for {package}"
        )
    try:
        return resp.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=502, detail=f"upstream returned non-json: {exc}"
        ) from exc


def _load_cached_metadata(package: str) -> dict[str, Any] | None:
    path = _metadata_path(package)
    if not path.exists():
        return None
    age = time.time() - path.stat().st_mtime
    if age > state.config.metadata_ttl_seconds:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _save_cached_metadata(package: str, metadata: dict[str, Any]) -> None:
    path = _metadata_path(package)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(metadata), encoding="utf-8")
    tmp.replace(path)


async def _get_metadata(package: str) -> dict[str, Any]:
    cached = _load_cached_metadata(package)
    if cached is not None:
        return cached
    metadata = await _fetch_upstream_metadata(package)
    _save_cached_metadata(package, metadata)
    return metadata


async def _fetch_upstream_tarball(
    package: str, version: str, filename: str
) -> bytes:
    assert state.client is not None
    url = f"{state.config.upstream}/{package}/-/{filename}"
    try:
        resp = await state.client.get(url)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"upstream error: {exc}") from exc
    if resp.status_code == 404:
        raise HTTPException(
            status_code=404, detail=f"tarball not found: {package}@{version}"
        )
    if resp.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"upstream {resp.status_code} for {package}@{version}",
        )
    return resp.content


def _load_or_fetch_tarball_sync(
    package: str, version: str, filename: str
) -> tuple[bytes, bool]:
    """Return ``(bytes, from_cache)``. Caller does async fetch on miss."""
    path = _tarball_path(package, version, filename)
    if path.exists():
        return path.read_bytes(), True
    return b"", False


def _save_tarball(
    package: str, version: str, filename: str, payload: bytes
) -> None:
    path = _tarball_path(package, version, filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(payload)
    tmp.replace(path)


def _filename_to_version(package: str, filename: str) -> str:
    """Extract the version from an npm tarball filename.

    Conventions::

        lodash-4.17.21.tgz                       -> 4.17.21
        @types__node-20.10.5.tgz                 -> 20.10.5 (rare upstream form)
        node-20.10.5.tgz under /@types/node/-/   -> 20.10.5

    For scoped packages the upstream filename uses the bare name (the scope
    is in the URL path), so the version is everything after the last hyphen
    preceding the .tgz suffix.
    """
    if not filename.endswith(".tgz"):
        raise ValueError(f"not a tarball filename: {filename}")
    stem = filename[: -len(".tgz")]
    # bare package name without scope
    bare = package.split("/")[-1]
    prefix = f"{bare}-"
    if stem.startswith(prefix):
        return stem[len(prefix):]
    # fall back: take the last hyphen split
    if "-" in stem:
        return stem.rsplit("-", 1)[1]
    raise ValueError(f"cannot parse version from {filename!r}")


def _write_audit_sidecar(
    package: str, version: str, decision: PolicyDecision
) -> None:
    path = _audit_sidecar_path(package, version)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "package": package,
        "version": version,
        "verdict": decision.verdict,
        "failed_rules": decision.failed_rules,
        "passed_rules": decision.passed_rules,
        "evidence": decision.evidence,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# ----------------------------------------------------------------------------
# Lifespan + app
# ----------------------------------------------------------------------------


def _build_registry(client: httpx.AsyncClient, ecosystem: str, upstream: str) -> Registry:
    """Construct the Registry implementation for the selected ecosystem."""
    if ecosystem == "pypi":
        return PyPIRegistry(client, upstream=upstream)
    if ecosystem == "composer":
        return ComposerRegistry(client, upstream=upstream)
    return NpmRegistry(client, upstream=upstream)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    state.client = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
        headers={"User-Agent": "apiary-proxy/0.1"},
    )
    state.config.cache_dir.mkdir(parents=True, exist_ok=True)
    state.config.audit_log.parent.mkdir(parents=True, exist_ok=True)
    state.config.source_cache_dir.mkdir(parents=True, exist_ok=True)
    state.reload_quarantine()
    state.registry = _build_registry(
        state.client, state.config.ecosystem, state.config.upstream
    )

    # Start LRU evictor for the tarball cache.
    state.evictor = LRUCacheEvictor(
        cache_dir=state.config.cache_dir,
        max_bytes=state.config.cache_max_bytes,
        sweep_interval_seconds=state.config.cache_sweep_seconds,
    )
    state.evictor.start()

    logger.info(
        "apiary proxy started; upstream=%s cache_dir=%s env=%s",
        state.config.upstream,
        state.config.cache_dir,
        state.config.environment,
    )
    yield
    await state.aclose()


app = FastAPI(title="Apiary Registry Proxy", version="0.1.0", lifespan=_lifespan)


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    cache_stats: dict[str, Any] | None = None
    if state.evictor is not None:
        cache_stats = state.evictor.stats.to_dict()
    return {
        "status": "ok",
        "upstream": state.config.upstream,
        "cache_dir": str(state.config.cache_dir),
        "quarantine_loaded": bool(state.quarantine_db),
        "environment": state.config.environment,
        "ecosystem": state.config.ecosystem,
        "cache_stats": cache_stats,
    }


# ----------------------------------------------------------------------------
# Cross-ecosystem helpers
# ----------------------------------------------------------------------------


async def _gate_with_registry(
    package: str, version: str, req: Request, *, filename: str | None = None
) -> Response:
    """Run a Registry-backed package through the policy gate.

    Shared by the PyPI and Composer routes. The npm routes keep their
    legacy direct httpx wiring so the metadata cache layout, on-disk
    audit sidecars, and dist.tarball rewriting all continue to work
    unchanged for existing demos.
    """
    if state.registry is None:
        raise HTTPException(status_code=503, detail="proxy not initialized")
    try:
        meta = await state.registry.get_metadata(package, version)
        payload = await state.registry.get_tarball(package, version)
    except PackageNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except UpstreamError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    npm_shape = metadata_to_npm_shape(meta)
    state.reload_quarantine()
    decision = await asyncio.to_thread(
        decide_policy,
        package=package,
        version=version,
        metadata=npm_shape,
        tarball_bytes=payload,
        quarantine_db=state.quarantine_db,
        min_age_days=state.config.min_age_days,
        environment=state.config.environment,
        env_config_path=state.config.env_config_path,
        source_cache_dir=state.config.source_cache_dir,
    )
    _write_audit_sidecar(package, version, decision)
    _audit(
        {
            "event": "tarball",
            "package": package,
            "version": version,
            "filename": filename or "",
            "ecosystem": meta.ecosystem,
            "bytes": len(payload),
            "verdict": decision.verdict,
            "failed_rules": decision.failed_rules,
            "client": req.headers.get("user-agent", ""),
        }
    )

    if decision.verdict == "block":
        return JSONResponse(
            status_code=451,
            content={
                "error": "blocked-by-apiary-policy",
                "package": package,
                "version": version,
                "ecosystem": meta.ecosystem,
                "failed_rules": decision.failed_rules,
                "evidence": decision.evidence,
            },
        )
    if decision.verdict == "quarantine":
        return JSONResponse(
            status_code=202,
            content={
                "status": "quarantined",
                "package": package,
                "version": version,
                "ecosystem": meta.ecosystem,
                "failed_rules": decision.failed_rules,
                "evidence": decision.evidence,
            },
        )
    return Response(content=payload, media_type="application/octet-stream")


# ----------------------------------------------------------------------------
# PyPI routes
# ----------------------------------------------------------------------------
#
# These routes only do anything useful when the proxy is started with
# ``--ecosystem pypi``. They are registered unconditionally so a single
# binary can serve any ecosystem on demand; the route handlers themselves
# refuse traffic when the configured ecosystem does not match.


def _require_ecosystem(expected: str) -> None:
    if state.config.ecosystem != expected:
        raise HTTPException(
            status_code=404,
            detail=(
                f"proxy is in {state.config.ecosystem!r} mode; "
                f"{expected!r} routes are not active"
            ),
        )


@app.get("/simple/{package}/")
async def pypi_simple_index(package: str, req: Request) -> Response:
    """Emit a minimal PEP 503 simple index for one package.

    The Python install index format that pip understands is HTML with one
    anchor per dist file. We render the same view from the PyPI Registry
    metadata so pip can resolve and download through the proxy.
    """
    _require_ecosystem("pypi")
    if state.registry is None:
        raise HTTPException(status_code=503, detail="proxy not initialized")
    canonical = state.registry.normalize_package_name(package)
    # PyPI's JSON API needs a specific version. The simple index lists
    # every version, so we proxy through to the upstream simple endpoint
    # rather than rebuild it from the JSON API per version.
    assert state.client is not None
    url = f"{state.registry.upstream_url()}/simple/{canonical}/"
    try:
        resp = await state.client.get(url, headers={"Accept": "text/html"})
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"upstream error: {exc}") from exc
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail=f"pypi package not found: {package}")
    if resp.status_code >= 400:
        raise HTTPException(
            status_code=502, detail=f"upstream {resp.status_code} for {package}"
        )
    _audit(
        {
            "event": "pypi_simple",
            "package": package,
            "client": req.headers.get("user-agent", ""),
        }
    )
    return Response(content=resp.content, media_type="text/html")


@app.get("/pypi/{package}/{version}/json")
async def pypi_metadata(package: str, version: str, req: Request) -> Response:
    """Return the PyPI JSON metadata for ``package@version``."""
    _require_ecosystem("pypi")
    if state.registry is None:
        raise HTTPException(status_code=503, detail="proxy not initialized")
    try:
        meta = await state.registry.get_metadata(package, version)
    except PackageNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except UpstreamError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    _audit(
        {
            "event": "pypi_metadata",
            "package": package,
            "version": version,
            "client": req.headers.get("user-agent", ""),
        }
    )
    return JSONResponse(meta.raw)


@app.get("/pypi/dist/{package}/{version}/{filename}")
async def pypi_dist(
    package: str, version: str, filename: str, req: Request
) -> Response:
    """Serve a PyPI distribution archive through the policy gate."""
    _require_ecosystem("pypi")
    return await _gate_with_registry(package, version, req, filename=filename)


# ----------------------------------------------------------------------------
# Composer routes
# ----------------------------------------------------------------------------


@app.get("/p2/{vendor}/{name}.json")
async def composer_metadata(
    vendor: str, name: str, req: Request
) -> Response:
    """Mirror the Packagist v2 metadata endpoint for ``vendor/name``."""
    _require_ecosystem("composer")
    if state.registry is None:
        raise HTTPException(status_code=503, detail="proxy not initialized")
    package = f"{vendor}/{name}"
    # Composer fetches the entire version list in one go; surface the
    # upstream document verbatim. The policy gate fires on dist fetch.
    assert state.client is not None
    canonical = state.registry.normalize_package_name(package)
    url = f"{state.registry.upstream_url()}/p2/{canonical}.json"
    try:
        resp = await state.client.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"upstream error: {exc}") from exc
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail=f"composer package not found: {package}")
    if resp.status_code >= 400:
        raise HTTPException(
            status_code=502, detail=f"upstream {resp.status_code} for {package}"
        )
    _audit(
        {
            "event": "composer_metadata",
            "package": package,
            "client": req.headers.get("user-agent", ""),
        }
    )
    return Response(content=resp.content, media_type="application/json")


@app.get("/dist/{vendor}/{name}/{version}.zip")
async def composer_dist(
    vendor: str, name: str, version: str, req: Request
) -> Response:
    """Serve a Composer dist archive through the policy gate."""
    _require_ecosystem("composer")
    package = f"{vendor}/{name}"
    return await _gate_with_registry(package, version, req, filename=f"{version}.zip")


@app.get("/-/ping")
def npm_ping() -> dict[str, Any]:
    return {"pong": True}


@app.post("/-/v1/login")
async def npm_login_stub(req: Request) -> JSONResponse:
    """Accept ``npm login`` posts so the CLI does not error.

    We are a read-only proxy; the token returned is decorative.
    """
    _audit({"event": "login_stub", "client": req.headers.get("user-agent", "")})
    return JSONResponse(
        {"token": "apiary-readonly", "ok": True, "message": "apiary proxy is read-only"}
    )


async def _serve_metadata(package: str, req: Request) -> Response:
    metadata = await _get_metadata(package)
    rewritten = _rewrite_tarballs(metadata, _public_base(req))
    _audit(
        {
            "event": "metadata",
            "package": package,
            "client": req.headers.get("user-agent", ""),
        }
    )
    return JSONResponse(rewritten)


async def _serve_tarball(
    package: str, filename: str, req: Request
) -> Response:
    try:
        version = _filename_to_version(package, filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    payload, from_cache = _load_or_fetch_tarball_sync(package, version, filename)
    if not from_cache:
        payload = await _fetch_upstream_tarball(package, version, filename)
        _save_tarball(package, version, filename, payload)
    else:
        # Touch the file so the LRU evictor treats it as recently used.
        if state.evictor is not None:
            state.evictor.touch(_tarball_path(package, version, filename))

    # Always re-evaluate policy at serve time. Metadata may be cached, but the
    # policy verdict is cheap to recompute and reflects current quarantine.
    metadata = await _get_metadata(package)
    state.reload_quarantine()

    # Source-match is the slowest rule (network IO + SHA256 over many files).
    # Run it off the event loop so we do not stall other proxy requests.
    decision = await asyncio.to_thread(
        decide_policy,
        package=package,
        version=version,
        metadata=metadata,
        tarball_bytes=payload,
        quarantine_db=state.quarantine_db,
        min_age_days=state.config.min_age_days,
        environment=state.config.environment,
        env_config_path=state.config.env_config_path,
        source_cache_dir=state.config.source_cache_dir,
    )
    _write_audit_sidecar(package, version, decision)
    _audit(
        {
            "event": "tarball",
            "package": package,
            "version": version,
            "filename": filename,
            "from_cache": from_cache,
            "bytes": len(payload),
            "verdict": decision.verdict,
            "failed_rules": decision.failed_rules,
            "client": req.headers.get("user-agent", ""),
        }
    )

    if decision.verdict == "block":
        return JSONResponse(
            status_code=451,
            content={
                "error": "blocked-by-apiary-policy",
                "package": package,
                "version": version,
                "failed_rules": decision.failed_rules,
                "evidence": decision.evidence,
            },
        )
    if decision.verdict == "quarantine":
        return JSONResponse(
            status_code=202,
            content={
                "status": "quarantined",
                "package": package,
                "version": version,
                "failed_rules": decision.failed_rules,
                "evidence": decision.evidence,
                "note": (
                    "tarball is cached but not served; promote via "
                    "apiary-quarantine promote"
                ),
            },
        )
    return Response(content=payload, media_type="application/octet-stream")


@app.get("/{package}")
async def metadata_unscoped(package: str, req: Request) -> Response:
    _require_ecosystem("npm")
    if package.startswith("@"):
        raise HTTPException(status_code=400, detail="use /@scope/name for scoped packages")
    if package.startswith("-"):
        raise HTTPException(status_code=404, detail="reserved npm namespace")
    return await _serve_metadata(package, req)


@app.get("/{package}/-/{filename}")
async def tarball_unscoped(package: str, filename: str, req: Request) -> Response:
    _require_ecosystem("npm")
    if not filename.endswith(".tgz"):
        raise HTTPException(status_code=400, detail="only .tgz tarballs are served")
    return await _serve_tarball(package, filename, req)


@app.get("/@{scope}/{name}")
async def metadata_scoped(scope: str, name: str, req: Request) -> Response:
    _require_ecosystem("npm")
    package = f"@{scope}/{name}"
    return await _serve_metadata(package, req)


@app.get("/@{scope}/{name}/-/{filename}")
async def tarball_scoped(
    scope: str, name: str, filename: str, req: Request
) -> Response:
    _require_ecosystem("npm")
    if not filename.endswith(".tgz"):
        raise HTTPException(status_code=400, detail="only .tgz tarballs are served")
    package = f"@{scope}/{name}"
    return await _serve_tarball(package, filename, req)


@app.get("/audit")
def audit_tail(limit: int = 50) -> list[dict[str, Any]]:
    limit = max(1, min(1000, limit))
    if not state.config.audit_log.exists():
        return []
    try:
        with state.config.audit_log.open(encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for raw in lines[-limit:]:
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out


# ----------------------------------------------------------------------------
# CLI entry
# ----------------------------------------------------------------------------


def _default_upstream_for(ecosystem: str) -> str:
    if ecosystem == "pypi":
        return DEFAULT_PYPI_UPSTREAM
    if ecosystem == "composer":
        return DEFAULT_COMPOSER_UPSTREAM
    return DEFAULT_UPSTREAM


def _configure(args: argparse.Namespace) -> None:
    env_name = args.environment or os.environ.get("APIARY_ENVIRONMENT", "preprod")
    env_config_path: Path | None = None
    if args.env_config:
        env_config_path = Path(args.env_config)
    elif os.environ.get("APIARY_ENV_CONFIG"):
        env_config_path = Path(os.environ["APIARY_ENV_CONFIG"])

    # If the caller did not override min_age_days on the CLI, fall back to the
    # per-environment default. The sentinel -1 means "use env default".
    cli_min_age = args.min_age_days if args.min_age_days >= 0 else None
    effective_min_age = cli_min_age
    if effective_min_age is None:
        effective_min_age = load_environment_policy(
            env_name, env_config_path
        ).min_release_age_days

    ecosystem = args.ecosystem or "npm"
    # Use the ecosystem-specific default upstream when the caller did not
    # override it. This keeps ``--ecosystem pypi`` working without forcing
    # the operator to also pass ``--upstream``.
    upstream = args.upstream
    if upstream == DEFAULT_UPSTREAM and ecosystem != "npm":
        upstream = _default_upstream_for(ecosystem)

    state.config = ProxyConfig(
        upstream=upstream,
        cache_dir=args.cache_dir,
        audit_log=args.audit_log,
        quarantine_dir=args.quarantine_dir,
        metadata_ttl_seconds=args.metadata_ttl,
        min_age_days=effective_min_age,
        public_base_url=args.public_base_url,
        environment=env_name,
        env_config_path=env_config_path,
        source_cache_dir=args.source_cache_dir,
        cache_max_bytes=args.cache_max_bytes,
        cache_sweep_seconds=args.cache_sweep_seconds,
        ecosystem=ecosystem,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="apiary-proxy")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4873)
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--audit-log", type=Path, default=DEFAULT_AUDIT_LOG)
    parser.add_argument(
        "--quarantine-dir", type=Path, default=DEFAULT_QUARANTINE_DIR
    )
    parser.add_argument("--metadata-ttl", type=int, default=METADATA_TTL_SECONDS)
    parser.add_argument(
        "--min-age-days",
        type=int,
        default=-1,
        help="override per-env min release age (negative = use environment default)",
    )
    parser.add_argument(
        "--public-base-url",
        default=None,
        help="optional explicit base URL for rewritten dist.tarball entries",
    )
    parser.add_argument(
        "--environment",
        default=None,
        help="env name (dev|preprod|prod); defaults to $APIARY_ENVIRONMENT or 'preprod'",
    )
    parser.add_argument(
        "--env-config",
        type=Path,
        default=None,
        help="path to YAML environment overrides; defaults to $APIARY_ENV_CONFIG",
    )
    parser.add_argument(
        "--source-cache-dir",
        type=Path,
        default=Path("data/source-cache"),
        help="cache dir for upstream source archives (source-match rule)",
    )
    parser.add_argument(
        "--cache-max-bytes",
        type=int,
        default=10 * 1024 * 1024 * 1024,
        help="LRU eviction threshold for the proxy tarball cache (bytes)",
    )
    parser.add_argument(
        "--cache-sweep-seconds",
        type=float,
        default=300.0,
        help="LRU eviction sweep interval (seconds)",
    )
    parser.add_argument(
        "--ecosystem",
        choices=("npm", "pypi", "composer"),
        default="npm",
        help=(
            "Which package ecosystem this proxy instance serves. The default "
            "upstream URL is selected automatically based on this choice."
        ),
    )
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    _configure(args)
    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required to run the proxy", file=sys.stderr)
        return 2

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level=args.log_level,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())


async def _amain_for_tests() -> None:  # pragma: no cover - placeholder
    """Hook so test harnesses can drive the lifespan manually."""
    async with _lifespan(app):
        await asyncio.sleep(0)
