"""Adapter for apetersson/ModuleWarden scraped-case.v1 records.

ModuleWarden's `finetune/scripts/scrape-cases.mjs` pulls GitHub Security
Advisories for npm, enriches with npm packument + OSV cross-references,
and emits JSONL records matching `modulewarden.scraped_case.v1`.

This adapter converts those records into apiary's SFT instruction-tuning
format so the H100 abliteration + SFT LoRA pipeline can train on real
GHSA-anchored cases.

Schema reference: `data/raw/scraped-ghsa/scraped-case.schema.json`
Sample input:    `data/raw/scraped-ghsa/scraped-cases.jsonl`
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path
from typing import Iterator

logger = logging.getLogger("apiary.scraped_case_adapter")


SYSTEM_PROMPT = (
    "You are an apiary security analyst auditing an npm package version "
    "against a Class A (compromised-maintainer) threat model. Produce a "
    "structured JSON verdict matching the apiary Decision contract."
)


def _format_user_prompt(case: dict) -> str:
    package = case.get("package", "unknown")
    advisory = (case.get("advisory_ids") or ["unknown"])[0]
    severity = case.get("severity") or "unknown"
    summary = case.get("summary") or "(no summary)"
    cwes = ", ".join(case.get("cwes") or []) or "none"
    affected = case.get("affected_range") or "unknown"
    patched = case.get("first_patched_version") or "unknown"
    npm_meta = case.get("npm") or {}
    repo_field = npm_meta.get("repository")
    if isinstance(repo_field, dict):
        repo = repo_field.get("url") or "unknown"
    elif isinstance(repo_field, str):
        repo = repo_field
    else:
        repo = "unknown"
    maintainers = npm_meta.get("maintainers") or []
    n_maint = len(maintainers)
    osv_ids = ", ".join(case.get("osv_ids") or []) or "none"

    return (
        f"Audit npm package version against Class A compromised-maintainer threat model.\n"
        f"\n"
        f"Package: {package}\n"
        f"Affected range: {affected}\n"
        f"First patched version: {patched}\n"
        f"Advisory: {advisory}\n"
        f"OSV cross-references: {osv_ids}\n"
        f"CWE(s): {cwes}\n"
        f"Severity: {severity}\n"
        f"Maintainer count: {n_maint}\n"
        f"Repository: {repo}\n"
        f"\n"
        f"Advisory summary: {summary}\n"
        f"\n"
        f"Return JSON with fields: verdict (allow|block|quarantine), threat_class "
        f"(A|B|C), confidence (0-1), reasoning (string), findings (list of strings)."
    )


def _derive_verdict(case: dict) -> dict:
    """Derive the ground-truth assistant response from GHSA evidence."""
    severity = (case.get("severity") or "").lower()
    case_type = case.get("case_type") or ""
    advisory_id = (case.get("advisory_ids") or ["unknown"])[0]
    package = case.get("package", "unknown")
    affected = case.get("affected_range") or "unspecified"
    patched = case.get("first_patched_version") or "unspecified"
    cwes = case.get("cwes") or []

    if severity == "critical":
        verdict, confidence = "block", 0.95
    elif severity == "high":
        verdict, confidence = "block", 0.88
    elif severity == "medium":
        verdict, confidence = "quarantine", 0.75
    else:
        verdict, confidence = "quarantine", 0.6

    if case_type == "incident_replay" and severity in ("high", "critical"):
        verdict = "block"
        confidence = 0.97

    findings = [
        f"GHSA advisory: {advisory_id}",
        f"Severity tier: {severity or 'unspecified'}",
    ]
    if cwes:
        findings.append("CWE classification: " + ", ".join(cwes))
    if affected != "unspecified":
        findings.append(f"Affected version range: {affected}")
    if patched != "unspecified":
        findings.append(f"Safe predecessor / first patched: {patched}")

    reasoning = (
        f"Package {package} carries a confirmed {severity or 'unspecified'}-severity "
        f"GHSA advisory ({advisory_id}). The affected range {affected} should be "
        f"refused or quarantined; the first patched release {patched} is the documented "
        f"safe replacement. CWE classification ({', '.join(cwes) or 'none'}) is "
        f"consistent with a Class A compromised-maintainer pattern that mutates "
        f"package behaviour without a corresponding semver-meaningful change."
    )

    return {
        "verdict": verdict,
        "threat_class": "A",
        "confidence": confidence,
        "reasoning": reasoning,
        "findings": findings,
    }


def case_to_sft(case: dict, split: str = "train") -> dict:
    """Transform one scraped-case.v1 record into apiary SFT chat format."""
    user_prompt = _format_user_prompt(case)
    verdict = _derive_verdict(case)
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
            {"role": "assistant", "content": json.dumps(verdict, ensure_ascii=False, indent=2)},
        ],
        "meta": {
            "source": "ghsa_scraper",
            "case_id": case.get("case_id"),
            "case_type": case.get("case_type"),
            "package": case.get("package"),
            "severity": case.get("severity"),
            "advisory_ids": case.get("advisory_ids") or [],
            "scraped_at": case.get("scraped_at"),
            "split": split,
        },
    }


def _iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def _stratified_split(cases: list[dict], train_frac: float, val_frac: float, seed: int) -> dict[str, list[dict]]:
    import random

    rng = random.Random(seed)
    by_severity: dict[str, list[dict]] = {}
    for case in cases:
        sev = (case.get("severity") or "unknown").lower()
        by_severity.setdefault(sev, []).append(case)

    train_rows, val_rows, test_rows = [], [], []
    for sev, bucket in by_severity.items():
        rng.shuffle(bucket)
        n = len(bucket)
        n_train = int(n * train_frac)
        n_val = int(n * val_frac)
        train_rows.extend(bucket[:n_train])
        val_rows.extend(bucket[n_train:n_train + n_val])
        test_rows.extend(bucket[n_train + n_val:])
    rng.shuffle(train_rows)
    rng.shuffle(val_rows)
    rng.shuffle(test_rows)
    return {"train": train_rows, "val": val_rows, "test": test_rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/raw/scraped-ghsa/scraped-cases.jsonl"),
        help="Scraped-case.v1 JSONL from ModuleWarden's GHSA scraper.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/sft/ghsa-cases-v1.jsonl"),
        help="Destination SFT JSONL.",
    )
    parser.add_argument("--train-frac", type=float, default=0.8)
    parser.add_argument("--val-frac", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--no-split",
        action="store_true",
        help="Skip splitting; emit all records to --output as one stream.",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.input.exists():
        logger.error("input not found: %s", args.input)
        return 1

    cases = list(_iter_jsonl(args.input))
    if not cases:
        logger.error("no cases found in %s", args.input)
        return 1
    logger.info("loaded %d scraped-case records from %s", len(cases), args.input)

    args.output.parent.mkdir(parents=True, exist_ok=True)

    if args.no_split:
        sft_records = [case_to_sft(case, split="train") for case in cases]
        with args.output.open("w", encoding="utf-8") as fh:
            for record in sft_records:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        logger.info("wrote %d SFT records to %s", len(sft_records), args.output)
    else:
        splits = _stratified_split(cases, args.train_frac, args.val_frac, args.seed)
        for split_name, bucket in splits.items():
            out_path = args.output.parent / f"{args.output.stem}-{split_name}{args.output.suffix}"
            with out_path.open("w", encoding="utf-8") as fh:
                for case in bucket:
                    fh.write(json.dumps(case_to_sft(case, split=split_name), ensure_ascii=False) + "\n")
            logger.info("wrote %d records to %s", len(bucket), out_path)

    verdict_counts: Counter[str] = Counter()
    for case in cases:
        verdict_counts[_derive_verdict(case)["verdict"]] += 1
    logger.info("verdict distribution: %s", dict(verdict_counts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
