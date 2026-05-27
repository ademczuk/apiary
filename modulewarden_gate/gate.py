"""FastAPI gate that turns model verdicts into allow / quarantine / block decisions.

Run:
    uvicorn modulewarden_gate.gate:app --port 8000 --reload

Endpoint:
    POST /score
    {
        "package": "event-stream",
        "version": "3.3.6"
    }

Response:
    {
        "package": "event-stream",
        "version": "3.3.6",
        "score": 0.97,
        "decision": "block",
        "evidence": ["dependency_swap_flatmap_stream", "exfil_to_external_host"],
        "model": "stub-v0"
    }

Thresholds live in modulewarden_gate/thresholds.yaml and are hot-reloaded on
each request so demo tweaks do not require a restart.

TODO:
    - Cache verdicts per (package, version) for a configurable TTL.
    - Add a /healthz that probes the underlying model.
    - Add request id and structured logs for the bridge to correlate.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from fastapi import FastAPI
from pydantic import BaseModel, Field

# Reuse the scoring logic from the CLI script
from scripts.score_package import decide, score

THRESHOLDS_PATH = Path(__file__).resolve().parent / "thresholds.yaml"

app = FastAPI(title="ModuleWarden Gate", version="0.1.0")


class ScoreRequest(BaseModel):
    package: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)


class ScoreResponse(BaseModel):
    package: str
    version: str
    score: float
    decision: str
    evidence: list[str]
    model: str


def _load_thresholds() -> dict:
    return yaml.safe_load(THRESHOLDS_PATH.read_text(encoding="utf-8"))


@app.get("/healthz")
def healthz() -> dict:
    """Liveness probe; bridge uses this before piping records."""
    return {"ok": True, "version": app.version}


@app.post("/score", response_model=ScoreResponse)
def score_endpoint(req: ScoreRequest) -> ScoreResponse:
    thresholds = _load_thresholds()
    verdict = score(req.package, req.version, model_path=None)
    verdict["decision"] = decide(verdict["score"], thresholds)
    return ScoreResponse(**verdict)
