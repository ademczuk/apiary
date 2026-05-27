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

from apiary_policy import PolicyDecision, decide_policy
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

    def __post_init__(self) -> None:
        self.cache_dir = Path(self.cache_dir)
        self.audit_log = Path(self.audit_log)
        self.quarantine_dir = Path(self.quarantine_dir)
        self.upstream = self.upstream.rstrip("/")


@dataclass
class ProxyState:
    config: ProxyConfig = field(default_factory=ProxyConfig)
    client: httpx.AsyncClient | None = None
    quarantine_db: dict[str, Any] = field(default_factory=dict)

    async def aclose(self) -> None:
        if self.client is not None:
            await self.client.aclose()
            self.client = None

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


@asynccontextmanager
async def _lifespan(app: FastAPI):
    state.client = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
        headers={"User-Agent": "apiary-proxy/0.1"},
    )
    state.config.cache_dir.mkdir(parents=True, exist_ok=True)
    state.config.audit_log.parent.mkdir(parents=True, exist_ok=True)
    state.reload_quarantine()
    logger.info(
        "apiary proxy started; upstream=%s cache_dir=%s",
        state.config.upstream,
        state.config.cache_dir,
    )
    yield
    await state.aclose()


app = FastAPI(title="Apiary Registry Proxy", version="0.1.0", lifespan=_lifespan)


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {
        "status": "ok",
        "upstream": state.config.upstream,
        "cache_dir": str(state.config.cache_dir),
        "quarantine_loaded": bool(state.quarantine_db),
    }


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

    # Always re-evaluate policy at serve time. Metadata may be cached, but the
    # policy verdict is cheap to recompute and reflects current quarantine.
    metadata = await _get_metadata(package)
    state.reload_quarantine()
    decision = decide_policy(
        package=package,
        version=version,
        metadata=metadata,
        tarball_bytes=payload,
        quarantine_db=state.quarantine_db,
        min_age_days=state.config.min_age_days,
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
    if package.startswith("@"):
        raise HTTPException(status_code=400, detail="use /@scope/name for scoped packages")
    if package.startswith("-"):
        raise HTTPException(status_code=404, detail="reserved npm namespace")
    return await _serve_metadata(package, req)


@app.get("/{package}/-/{filename}")
async def tarball_unscoped(package: str, filename: str, req: Request) -> Response:
    if not filename.endswith(".tgz"):
        raise HTTPException(status_code=400, detail="only .tgz tarballs are served")
    return await _serve_tarball(package, filename, req)


@app.get("/@{scope}/{name}")
async def metadata_scoped(scope: str, name: str, req: Request) -> Response:
    package = f"@{scope}/{name}"
    return await _serve_metadata(package, req)


@app.get("/@{scope}/{name}/-/{filename}")
async def tarball_scoped(
    scope: str, name: str, filename: str, req: Request
) -> Response:
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


def _configure(args: argparse.Namespace) -> None:
    state.config = ProxyConfig(
        upstream=args.upstream,
        cache_dir=args.cache_dir,
        audit_log=args.audit_log,
        quarantine_dir=args.quarantine_dir,
        metadata_ttl_seconds=args.metadata_ttl,
        min_age_days=args.min_age_days,
        public_base_url=args.public_base_url,
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
    parser.add_argument("--min-age-days", type=int, default=14)
    parser.add_argument(
        "--public-base-url",
        default=None,
        help="optional explicit base URL for rewritten dist.tarball entries",
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
