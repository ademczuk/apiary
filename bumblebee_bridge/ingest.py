"""Pipe Bumblebee NDJSON into the ModuleWarden gate and render the table.

Reads NDJSON from stdin (or --input file path), filters to
record_type=package + ecosystem=npm, posts each to the gate concurrently
(bounded by --max-concurrent), and prints a table of decisions. Exits non-zero
if any package receives a `block` decision so this can be used as a CI gate.

Usage:
    bumblebee scan --profile project | python -m bumblebee_bridge.ingest
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


def _setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def iter_npm_packages(lines: Iterable[str]) -> Iterable[dict]:
    """Yield {package, version, source_file, confidence} for npm package records."""
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


async def _score_one(
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
    return verdict


async def _process(
    packages: list[dict],
    gate_url: str,
    max_concurrent: int,
    timeout: float,
) -> list[dict]:
    sem = asyncio.Semaphore(max_concurrent)
    timeout_cfg = httpx.Timeout(timeout, connect=10.0)
    async with httpx.AsyncClient(timeout=timeout_cfg) as client:
        tasks = [_score_one(client, gate_url, pkg, sem) for pkg in packages]
        return await asyncio.gather(*tasks)


def _render_table_plain(rows: list[dict], threshold: float) -> None:
    filtered = [r for r in rows if r.get("score", -1.0) >= threshold]
    if not filtered:
        print("(no rows above threshold)")
        return
    cols = ("package", "version", "score", "decision", "evidence")
    widths = {c: len(c) for c in cols}
    rendered: list[dict] = []
    for r in filtered:
        evidence = ", ".join(r.get("evidence", []) or [])
        line = {
            "package": str(r.get("package", "")),
            "version": str(r.get("version", "")),
            "score": f"{r.get('score', -1.0):.3f}",
            "decision": str(r.get("decision", "")),
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


def _render_table_rich(rows: list[dict], threshold: float) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        return _render_table_plain(rows, threshold)

    filtered = [r for r in rows if r.get("score", -1.0) >= threshold]
    console = Console()
    if not filtered:
        console.print("(no rows above threshold)")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("package")
    table.add_column("version")
    table.add_column("score", justify="right")
    table.add_column("decision")
    table.add_column("evidence")

    for r in filtered:
        decision = str(r.get("decision", ""))
        decision_style = {
            "block": "red",
            "quarantine": "yellow",
            "allow": "green",
            "error": "magenta",
        }.get(decision, "")
        evidence = ", ".join(r.get("evidence", []) or [])
        table.add_row(
            str(r.get("package", "")),
            str(r.get("version", "")),
            f"{r.get('score', -1.0):.3f}",
            f"[{decision_style}]{decision}[/{decision_style}]" if decision_style else decision,
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
    parser.add_argument("--gate-url", default="http://localhost:4873")
    parser.add_argument("--input", type=Path, default=None, help="NDJSON file (default stdin)")
    parser.add_argument("--threshold", type=float, default=0.0)
    parser.add_argument("--max-concurrent", type=int, default=10)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--json", action="store_true", help="emit NDJSON instead of a table")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    raw_lines = _read_input_lines(args.input)
    packages = list(iter_npm_packages(raw_lines))
    logger.info("parsed %d npm package records", len(packages))

    if not packages:
        if args.json:
            return 0
        print("(no npm packages in input)")
        return 0

    rows = asyncio.run(
        _process(packages, args.gate_url, args.max_concurrent, args.timeout)
    )

    if args.json:
        for r in rows:
            sys.stdout.write(json.dumps(r, ensure_ascii=False) + "\n")
    else:
        _render_table_rich(rows, args.threshold)

    any_block = any(r.get("decision") == "block" for r in rows)
    return 1 if any_block else 0


if __name__ == "__main__":
    sys.exit(main())
