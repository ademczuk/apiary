"""Self-contained smoke test for the Bumblebee -> apiary v2 proxy bridge.

Boots a tiny stub of the v2 proxy on localhost (no real npm registry, no
real tarballs), generates a fake Bumblebee NDJSON scan with a mix of
benign and malicious packages, pipes it through
``bumblebee_bridge.ingest --mode proxy``, and asserts the rendered table
shows ``postmark-mcp@1.0.16`` as ``block``.

Designed to run in CI without network access. Exit code 0 = success.
"""

from __future__ import annotations

import json
import logging
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger("apiary.bridge.smoke")

BLOCKED_PKG = "postmark-mcp"
BLOCKED_VER = "1.0.16"

FAKE_PACKAGES: list[dict[str, Any]] = [
    {"package": "lodash", "version": "4.17.21", "expected": "allow"},
    {"package": "react", "version": "18.2.0", "expected": "allow"},
    {"package": "express", "version": "4.18.2", "expected": "allow"},
    {"package": "axios", "version": "1.6.2", "expected": "allow"},
    {"package": "postmark-mcp", "version": "1.0.12", "expected": "allow"},
    {"package": "postmark-mcp", "version": BLOCKED_VER, "expected": "block"},
    {"package": "moment", "version": "2.29.4", "expected": "allow"},
    {"package": "typescript", "version": "5.3.3", "expected": "allow"},
]


def _ndjson_payload() -> str:
    """Render the fake scan as Bumblebee NDJSON."""
    lines: list[str] = []
    for entry in FAKE_PACKAGES:
        record = {
            "record_type": "package",
            "ecosystem": "npm",
            "normalized_name": entry["package"],
            "version": entry["version"],
            "source_file": f"package-lock.json#{entry['package']}",
            "confidence": "exact",
        }
        lines.append(json.dumps(record))
    return "\n".join(lines) + "\n"


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _start_stub_proxy(port: int) -> threading.Thread:
    """Start the stub FastAPI app in a daemon thread on the given port."""
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse, Response
    import uvicorn

    app = FastAPI()

    @app.get("/healthz")
    def _health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/{package:path}")
    def _route(package: str) -> Response:
        # The bridge first GETs /{package} (metadata), then
        # /{package}/-/{filename}.tgz (tarball). Both routes terminate here.
        if "/-/" in package:
            pkg, filename = package.split("/-/", 1)
            short = pkg.split("/")[-1] if pkg.startswith("@") else pkg
            stem = filename.removesuffix(".tgz")
            version = stem[len(short) + 1 :] if stem.startswith(f"{short}-") else stem
            if pkg == BLOCKED_PKG and version == BLOCKED_VER:
                return JSONResponse(
                    status_code=451,
                    content={
                        "error": "blocked-by-apiary-policy",
                        "package": pkg,
                        "version": version,
                        "failed_rules": ["known_quarantine"],
                        "evidence": ["explicitly blocked: smoke-test fixture"],
                    },
                )
            return Response(content=b"tarball-bytes", media_type="application/octet-stream")
        # Metadata: minimal shape, enough to satisfy the bridge.
        return JSONResponse({"name": package, "versions": {}})

    config = uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="warning", access_log=False
    )
    server = uvicorn.Server(config)

    def _serve() -> None:
        try:
            server.run()
        except SystemExit:
            pass

    thread = threading.Thread(target=_serve, name="stub-proxy", daemon=True)
    thread.start()

    # Wait for liveness (up to 5s).
    deadline = time.time() + 5.0
    while time.time() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.25)
                sock.connect(("127.0.0.1", port))
                return thread
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"stub proxy did not come up on :{port}")


def _run_bridge(port: int, ndjson_path: Path) -> tuple[int, str]:
    """Invoke the bridge as a subprocess and capture (exit_code, output)."""
    repo_root = Path(__file__).resolve().parent.parent
    cmd = [
        sys.executable,
        "-m",
        "bumblebee_bridge.ingest",
        "--mode",
        "proxy",
        "--proxy-url",
        f"http://127.0.0.1:{port}",
        "--input",
        str(ndjson_path),
        "--json",
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, cwd=str(repo_root), timeout=60
    )
    return result.returncode, result.stdout + result.stderr


def _assert_blocked(output: str) -> None:
    """Parse the bridge's JSON output and check that the blocked entry is present."""
    rows: list[dict[str, Any]] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not rows:
        raise AssertionError(f"bridge produced no JSON rows. raw output:\n{output}")

    by_key = {(r.get("package"), r.get("version")): r for r in rows}
    target = by_key.get((BLOCKED_PKG, BLOCKED_VER))
    if target is None:
        raise AssertionError(
            f"expected row for {BLOCKED_PKG}@{BLOCKED_VER}; got keys={list(by_key)}"
        )
    if target.get("decision") != "block":
        raise AssertionError(
            f"expected block for {BLOCKED_PKG}@{BLOCKED_VER}; got {target}"
        )
    if target.get("proxy_status") != 451:
        raise AssertionError(
            f"expected proxy_status=451 for {BLOCKED_PKG}@{BLOCKED_VER}; got {target}"
        )

    benign_rows = [
        r for k, r in by_key.items() if k != (BLOCKED_PKG, BLOCKED_VER)
    ]
    bad_benign = [
        r for r in benign_rows if r.get("decision") not in ("allow", "not-found")
    ]
    if bad_benign:
        raise AssertionError(
            f"benign packages got unexpected verdicts: {bad_benign}"
        )

    print(f"[smoke] verified BLOCK for {BLOCKED_PKG}@{BLOCKED_VER}")
    print(f"[smoke] verified {len(benign_rows)} benign packages were allowed")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    port = _pick_free_port()
    logger.info("starting stub proxy on 127.0.0.1:%d", port)
    _start_stub_proxy(port)

    with tempfile.TemporaryDirectory() as tmp:
        ndjson = Path(tmp) / "scan.ndjson"
        ndjson.write_text(_ndjson_payload(), encoding="utf-8")
        logger.info("wrote %d package records to %s", len(FAKE_PACKAGES), ndjson)

        rc, output = _run_bridge(port, ndjson)
        logger.info("bridge exited with code %d", rc)

    print("--- bridge output ---")
    print(output)
    print("---------------------")

    _assert_blocked(output)

    if rc != 1:
        raise AssertionError(
            f"expected bridge exit code 1 (block triggers CI gate); got {rc}"
        )

    print("[smoke] PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as exc:
        print(f"[smoke] FAIL: {exc}", file=sys.stderr)
        sys.exit(2)
