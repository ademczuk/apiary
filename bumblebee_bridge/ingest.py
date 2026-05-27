"""Pipe Bumblebee NDJSON into the ModuleWarden gate or apiary v2 proxy.

Reads NDJSON from stdin (or ``--input`` file path), filters to
``record_type=package`` and ``ecosystem=npm``, asks the configured backend
for a verdict on each, and prints a table of decisions. Exits non-zero if
any package is blocked so the script can be used as a CI gate.

Two backends are supported via ``--mode``:

* ``gate`` (legacy): POST each package to ``modulewarden_gate /score``.
* ``proxy`` (default, v2): GET ``/{package}`` for metadata, then GET
  ``/{package}/-/{filename}.tgz`` to drive the apiary v2 proxy through its
  policy gate. HTTP 200 = allow, 202 = quarantine, 451 = block, other =
  error.

Usage:
    bumblebee scan --profile project | python -m bumblebee_bridge.ingest
    python -m bumblebee_bridge.ingest --input scan.ndjson --mode gate
    python -m bumblebee_bridge.ingest --input scan.ndjson --json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Iterable

import httpx

logger = logging.getLogger("apiary.bridge")

DEFAULT_PROXY_URL = "http://localhost:4873"


def _setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def iter_npm_packages(lines: Iterable[str]) -> Iterable[dict]:
    """Yield ``{package, version, source_file, confidence}`` for npm records."""
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("record_type") != "package":
            continue
        if record.get("ecosystem") != "npm":
            continue
        name = record.get("normalized_name") or record.get("package_name")
        version = record.get("version")
        if not name or not version:
            continue
        yield {
            "package": str(name),
            "version": str(version),
            "source_file": record.get("source_file", ""),
            "confidence": record.get("confidence", ""),
        }


def _decision_from_status(status: int) -> str:
    """Map an HTTP status returned by the proxy to a textual decision."""
    if status == 200:
        return "allow"
    if status == 202:
        return "quarantine"
    if status == 451:
        return "block"
    if status == 404:
        return "not-found"
    return "error"


def _tarball_filename(package: str, version: str) -> str:
    """Build the standard npm tarball filename for a package version."""
    # Scoped names like @scope/name use the name part only in the tarball.
    short = package.split("/")[-1] if package.startswith("@") else package
    return f"{short}-{version}.tgz"


def _extract_reason(payload: dict | str, status: int) -> str:
    """Pull a short reason string from a proxy JSON response."""
    if isinstance(payload, str):
        return payload[:80]
    if not isinstance(payload, dict):
        return ""
    if status == 451:
        rules = payload.get("failed_rules") or []
        if rules:
            return ",".join(str(r) for r in rules)[:80]
        return str(payload.get("error", ""))[:80]
    if status == 202:
        rules = payload.get("failed_rules") or []
        if rules:
            return f"quarantine: {','.join(str(r) for r in rules)}"[:80]
        return str(payload.get("note", ""))[:80]
    if status == 404:
        return "not-found"
    if status >= 400:
        return str(payload.get("detail") or payload.get("error", ""))[:80]
    return ""


async def _score_one_gate(
    client: httpx.AsyncClient,
    gate_url: str,
    pkg: dict,
    semaphore: asyncio.Semaphore,
) -> dict:
    async with semaphore:
        try:
            resp = await client.post(
                f"{gate_url.rstrip('/')}/score",
                json={"package": pkg["package"], "version": pkg["version"]},
            )
            resp.raise_for_status()
            verdict = resp.json()
        except httpx.HTTPError as exc:
            verdict = {
                "package": pkg["package"],
                "version": pkg["version"],
                "score": -1.0,
                "decision": "error",
                "evidence": [f"gate_error: {exc}"],
            }
    verdict["source_file"] = pkg.get("source_file", "")
    verdict["mode"] = "gate"
    return verdict


async def _score_one_proxy(
    client: httpx.AsyncClient,
    proxy_url: str,
    pkg: dict,
    semaphore: asyncio.Semaphore,
) -> dict:
    """Drive the v2 proxy: metadata GET then tarball GET."""
    package = pkg["package"]
    version = pkg["version"]
    base = proxy_url.rstrip("/")
    out: dict = {
        "package": package,
        "version": version,
        "source_file": pkg.get("source_file", ""),
        "score": -1.0,
        "mode": "proxy",
    }

    async with semaphore:
        try:
            meta_resp = await client.get(f"{base}/{package}")
        except httpx.HTTPError as exc:
            out["decision"] = "error"
            out["proxy_status"] = -1
            out["reason"] = f"metadata_error: {exc}"
            out["evidence"] = [out["reason"]]
            return out

        meta_status = meta_resp.status_code
        if meta_status >= 400 and meta_status != 451:
            payload = _safe_json(meta_resp)
            out["decision"] = _decision_from_status(meta_status)
            out["proxy_status"] = meta_status
            out["reason"] = _extract_reason(payload, meta_status)
            out["evidence"] = [out["reason"]] if out["reason"] else []
            return out

        filename = _tarball_filename(package, version)
        try:
            tar_resp = await client.get(f"{base}/{package}/-/{filename}")
        except httpx.HTTPError as exc:
            out["decision"] = "error"
            out["proxy_status"] = -1
            out["reason"] = f"tarball_error: {exc}"
            out["evidence"] = [out["reason"]]
            return out

    status = tar_resp.status_code
    payload = _safe_json(tar_resp) if status != 200 else {}
    out["decision"] = _decision_from_status(status)
    out["proxy_status"] = status
    out["reason"] = _extract_reason(payload, status)
    out["evidence"] = (
        list(payload.get("failed_rules", []))
        if isinstance(payload, dict)
        else []
    )
    return out


def _safe_json(resp: httpx.Response) -> dict | str:
    """Parse a response body as JSON, falling back to text."""
    try:
        return resp.json()
    except (ValueError, json.JSONDecodeError):
        return resp.text


async def _process(
    packages: list[dict],
    backend_url: str,
    mode: str,
    max_concurrent: int,
    timeout: float,
) -> list[dict]:
    sem = asyncio.Semaphore(max_concurrent)
    timeout_cfg = httpx.Timeout(timeout, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout_cfg) as client:
        if mode == "gate":
            tasks = [_score_one_gate(client, backend_url, p, sem) for p in packages]
        else:
            tasks = [_score_one_proxy(client, backend_url, p, sem) for p in packages]
        return await asyncio.gather(*tasks)


def _render_table_plain(rows: list[dict], mode: str) -> None:
    if not rows:
        print("(no rows)")
        return
    if mode == "proxy":
        cols = ("package", "version", "source_file", "proxy_status", "decision", "reason")
    else:
        cols = ("package", "version", "score", "decision", "evidence")

    widths = {c: len(c) for c in cols}
    rendered: list[dict] = []
    for r in rows:
        evidence = ", ".join(r.get("evidence", []) or [])
        line = {
            "package": str(r.get("package", "")),
            "version": str(r.get("version", "")),
            "source_file": str(r.get("source_file", ""))[:30],
            "proxy_status": str(r.get("proxy_status", "")),
            "decision": str(r.get("decision", "")),
            "reason": str(r.get("reason", ""))[:60],
            "score": f"{r.get('score', -1.0):.3f}",
            "evidence": evidence[:60],
        }
        for c in cols:
            widths[c] = max(widths[c], len(line[c]))
        rendered.append(line)

    header = "  ".join(c.upper().ljust(widths[c]) for c in cols)
    print(header)
    print("-" * len(header))
    for line in rendered:
        print("  ".join(line[c].ljust(widths[c]) for c in cols))


def _render_table_rich(rows: list[dict], mode: str) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        return _render_table_plain(rows, mode)

    console = Console()
    if not rows:
        console.print("(no rows)")
        return

    table = Table(show_header=True, header_style="bold")
    if mode == "proxy":
        table.add_column("package")
        table.add_column("version")
        table.add_column("source-file")
        table.add_column("proxy-status", justify="right")
        table.add_column("decision")
        table.add_column("reason")
    else:
        table.add_column("package")
        table.add_column("version")
        table.add_column("score", justify="right")
        table.add_column("decision")
        table.add_column("evidence")

    decision_style = {
        "block": "red",
        "quarantine": "yellow",
        "allow": "green",
        "error": "magenta",
        "not-found": "blue",
    }

    for r in rows:
        decision = str(r.get("decision", ""))
        style = decision_style.get(decision, "")
        styled = f"[{style}]{decision}[/{style}]" if style else decision

        if mode == "proxy":
            table.add_row(
                str(r.get("package", "")),
                str(r.get("version", "")),
                str(r.get("source_file", ""))[:30],
                str(r.get("proxy_status", "")),
                styled,
                str(r.get("reason", ""))[:80],
            )
        else:
            evidence = ", ".join(r.get("evidence", []) or [])
            table.add_row(
                str(r.get("package", "")),
                str(r.get("version", "")),
                f"{r.get('score', -1.0):.3f}",
                styled,
                evidence[:80],
            )

    console.print(table)


def _read_input_lines(path: Path | None) -> list[str]:
    if path is None:
        return sys.stdin.readlines()
    with path.open(encoding="utf-8") as f:
        return f.readlines()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("gate", "proxy"),
        default="proxy",
        help="backend to query: legacy ModuleWarden gate or v2 apiary proxy",
    )
    parser.add_argument(
        "--proxy-url",
        default=DEFAULT_PROXY_URL,
        help=f"base URL for the v2 proxy (default: {DEFAULT_PROXY_URL})",
    )
    parser.add_argument(
        "--gate-url",
        default=DEFAULT_PROXY_URL,
        help="base URL for the legacy ModuleWarden gate",
    )
    parser.add_argument("--input", type=Path, default=None, help="NDJSON file (default stdin)")
    parser.add_argument("--max-concurrent", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--json", action="store_true", help="emit NDJSON instead of a table")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    raw_lines = _read_input_lines(args.input)
    packages = list(iter_npm_packages(raw_lines))
    logger.info("parsed %d npm package records (mode=%s)", len(packages), args.mode)

    if not packages:
        if args.json:
            return 0
        print("(no npm packages in input)")
        return 0

    backend_url = args.proxy_url if args.mode == "proxy" else args.gate_url
    rows = asyncio.run(
        _process(packages, backend_url, args.mode, args.max_concurrent, args.timeout)
    )

    if args.json:
        for r in rows:
            sys.stdout.write(json.dumps(r, ensure_ascii=False) + "\n")
    else:
        _render_table_rich(rows, args.mode)

    any_block = any(r.get("decision") == "block" for r in rows)
    if any_block:
        logger.warning("at least one package was blocked; exiting non-zero")
    return 1 if any_block else 0


if __name__ == "__main__":
    sys.exit(main())
