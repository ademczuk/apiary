"""FastAPI gate exposing /score and /audit for the ModuleWarden classifier.

Endpoints:
    POST /score    body {package, version, tarball_url?} -> verdict JSON
    GET  /audit    ?limit=N -> recent decisions from the audit log
    GET  /healthz  -> liveness + model status

Audit log lives at modulewarden_gate/audit.log (JSONL) and rotates at 10 MB.
Model loads at startup; if absent, runs heuristics-only and logs a warning.

Run:
    uvicorn modulewarden_gate.gate:app --host 0.0.0.0 --port 4873
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import httpx
import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, HttpUrl

from scripts.score_package import (
    decide,
    load_thresholds,
    score_package,
)

logger = logging.getLogger("apiary.gate")

GATE_DIR = Path(__file__).resolve().parent
THRESHOLDS_PATH = GATE_DIR / "thresholds.yaml"
AUDIT_LOG_PATH = GATE_DIR / "audit.log"
AUDIT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
MODEL_ENV = "APIARY_MODEL_PATH"

# SSRF guard: tarball_url must resolve to one of these hosts. Override via
# the APIARY_TARBALL_HOSTS env var (comma-separated).
DEFAULT_TARBALL_HOSTS: tuple[str, ...] = (
    "registry.npmjs.org",
    "registry.yarnpkg.com",
)
TARBALL_HOSTS_ENV = "APIARY_TARBALL_HOSTS"


def _allowed_tarball_hosts() -> set[str]:
    raw = os.environ.get(TARBALL_HOSTS_ENV)
    if not raw:
        return set(DEFAULT_TARBALL_HOSTS)
    return {h.strip().lower() for h in raw.split(",") if h.strip()}


def _validate_tarball_url(url: str) -> None:
    """Reject any tarball_url whose host is not in the allowlist (SSRF guard)."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400, detail=f"unsupported tarball scheme: {parsed.scheme!r}"
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise HTTPException(status_code=400, detail="tarball_url has no host")
    if host not in _allowed_tarball_hosts():
        raise HTTPException(
            status_code=400,
            detail=(
                f"tarball host {host!r} not in allowlist; set {TARBALL_HOSTS_ENV} "
                f"to override"
            ),
        )


class ScoreRequest(BaseModel):
    package: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    tarball_url: HttpUrl | None = None


class ScoreResponse(BaseModel):
    package: str
    version: str
    score: float
    decision: str
    evidence: list[str]
    model: str


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_path: str | None
    audit_count: int
    version: str


class AuditEntry(BaseModel):
    ts: str
    package: str
    version: str
    score: float
    decision: str
    evidence: list[str]
    model: str


class _GateState:
    def __init__(self) -> None:
        self.model_path: Path | None = None
        self.thresholds: dict = {}
        self.audit_count: int = 0
        self.startup_ts: float = time.time()
        self.recent: deque[dict] = deque(maxlen=1000)

    def reload_thresholds(self) -> None:
        self.thresholds = load_thresholds(THRESHOLDS_PATH)

    def resolve_model(self) -> None:
        env_path = os.environ.get(MODEL_ENV)
        if env_path:
            p = Path(env_path)
            if p.exists():
                self.model_path = p
                logger.info("model loaded from %s", p)
                return
            logger.warning("APIARY_MODEL_PATH set but missing: %s", env_path)
        self.model_path = None
        logger.warning(
            "no model artifact; running in heuristics-only mode (set %s to enable)",
            MODEL_ENV,
        )

    def append_audit(self, entry: dict) -> None:
        _rotate_if_needed(AUDIT_LOG_PATH, AUDIT_MAX_BYTES)
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self.audit_count += 1
        self.recent.append(entry)


state = _GateState()


def _rotate_if_needed(path: Path, max_bytes: int) -> None:
    try:
        if path.exists() and path.stat().st_size >= max_bytes:
            rotated = path.with_suffix(path.suffix + f".{int(time.time())}")
            path.rename(rotated)
            logger.info("rotated audit log to %s", rotated)
    except OSError as exc:
        logger.warning("audit rotation failed: %s", exc)


def _count_audit_lines(path: Path) -> int:
    if not path.exists():
        return 0
    n = 0
    with path.open("rb") as f:
        for _ in f:
            n += 1
    return n


@asynccontextmanager
async def _lifespan(app: FastAPI):
    state.reload_thresholds()
    state.resolve_model()
    state.audit_count = _count_audit_lines(AUDIT_LOG_PATH)
    logger.info("gate started; audit_count=%d", state.audit_count)
    yield


app = FastAPI(
    title="ModuleWarden Gate",
    version="0.1.0",
    lifespan=_lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


async def _download_tarball(url: str, dest: Path) -> None:
    timeout = httpx.Timeout(30.0, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            with dest.open("wb") as f:
                async for chunk in resp.aiter_bytes(chunk_size=64 * 1024):
                    f.write(chunk)


def _score_blocking(package_path: Path) -> dict:
    """Synchronous scoring; called from a thread pool to avoid blocking the loop."""
    return score_package(package_path, state.model_path, state.thresholds)


@app.get("/healthz", response_model=HealthResponse)
def healthz() -> HealthResponse:
    return HealthResponse(
        status="ok",
        model_loaded=state.model_path is not None,
        model_path=str(state.model_path) if state.model_path else None,
        audit_count=state.audit_count,
        version=app.version,
    )


@app.post("/score", response_model=ScoreResponse)
async def score_endpoint(req: ScoreRequest) -> ScoreResponse:
    state.reload_thresholds()

    with tempfile.TemporaryDirectory(prefix="apiary-gate-") as tmp:
        work = Path(tmp)
        if req.tarball_url:
            url_str = str(req.tarball_url)
            _validate_tarball_url(url_str)
            tarball = work / f"{req.package}-{req.version}.tgz"
            try:
                await _download_tarball(url_str, tarball)
            except httpx.HTTPError as exc:
                raise HTTPException(
                    status_code=502, detail=f"tarball download failed: {exc}"
                ) from exc
            package_path = tarball
        else:
            # Fetch the canonical npm registry tarball
            url = (
                f"https://registry.npmjs.org/{req.package}/-/"
                f"{req.package}-{req.version}.tgz"
            )
            tarball = work / f"{req.package}-{req.version}.tgz"
            try:
                await _download_tarball(url, tarball)
            except httpx.HTTPError as exc:
                raise HTTPException(
                    status_code=502,
                    detail=(
                        f"could not fetch {req.package}@{req.version} from "
                        f"npm registry: {exc}"
                    ),
                ) from exc
            package_path = tarball

        try:
            verdict = await asyncio.to_thread(_score_blocking, package_path)
        except (FileNotFoundError, ValueError, OSError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Ensure response honours the requested package/version even if package.json disagrees
    verdict.setdefault("package", req.package)
    verdict.setdefault("version", req.version)
    if not verdict.get("decision"):
        verdict["decision"] = decide(verdict["score"], state.thresholds)

    audit_entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "package": verdict["package"],
        "version": verdict["version"],
        "score": float(verdict["score"]),
        "decision": verdict["decision"],
        "evidence": list(verdict.get("evidence", [])),
        "model": verdict.get("model", "unknown"),
    }
    state.append_audit(audit_entry)
    return ScoreResponse(**verdict)


def _tail_audit(path: Path, limit: int) -> Iterable[dict]:
    if not path.exists():
        return []
    if limit <= 0:
        return []
    # Cheap tail: read all lines (audit caps at 10 MB so this is bounded)
    with path.open(encoding="utf-8") as f:
        lines = f.readlines()
    out: list[dict] = []
    for raw in lines[-limit:]:
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except json.JSONDecodeError:
            continue
    return out


@app.get("/audit", response_model=list[AuditEntry])
def audit_endpoint(limit: int = 50) -> list[AuditEntry]:
    limit = max(1, min(1000, limit))
    rows = list(_tail_audit(AUDIT_LOG_PATH, limit))
    return [AuditEntry(**r) for r in rows]
