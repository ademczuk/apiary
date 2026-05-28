"""Build the 4-cell evaluation matrix test set + config.

Andreas's eval matrix has two axes:

    rows = {vanilla base model, apiary-finetuned}
    cols = {one-shot inference, agentic tool-use inference}

This script does NOT run the eval. It produces the artifacts an eval
runner consumes:

- ``data/eval/matrix-test-set.jsonl``      held-out VersionPair test cases
- ``data/eval/matrix-config.yaml``          arm definitions + expected behavior
- ``data/eval/matrix-results-template.yaml``  empty results scaffold per arm

The held-out set is sampled deterministically from the version-pairs
output. We stratify by severity so each arm reports roughly comparable
class balance.

Pipeline position::

    extract_version_pairs.py  ->  data/raw/version-pairs/
    build_eval_matrix.py  <-- THIS  ->  data/eval/{matrix-*}
    [Andreas's eval runner consumes these on his end]
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

# Allow run-as-script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apiary_train.version_pair_extractor import (  # noqa: E402
    FileChange,
    VersionPair,
)

logger = logging.getLogger("apiary.build_eval_matrix")


def _iter_pairs(input_root: Path) -> Iterator[VersionPair]:
    for pair_json in input_root.rglob("pair.json"):
        try:
            data = json.loads(pair_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("bad pair.json skipped: %s (%s)", pair_json, exc)
            continue
        if data.get("extraction_method") != "tarball_diff":
            continue
        file_changes = [
            FileChange(**fc) for fc in (data.get("file_changes") or [])
        ]
        yield VersionPair(
            package=data["package"],
            unpatched_version=data["unpatched_version"],
            patched_version=data["patched_version"],
            advisory_ids=list(data.get("advisory_ids") or []),
            severity=data.get("severity") or "unknown",
            file_changes=file_changes,
            package_json_changes=data.get("package_json_changes") or {},
            extraction_method=data["extraction_method"],
            notes=list(data.get("notes") or []),
        )


def _stratified_sample(
    pairs: list[VersionPair], n: int, seed: int
) -> list[VersionPair]:
    rng = random.Random(seed)
    by_sev: dict[str, list[VersionPair]] = defaultdict(list)
    for p in pairs:
        by_sev[(p.severity or "unknown").lower()].append(p)
    for bucket in by_sev.values():
        rng.shuffle(bucket)
    selected: list[VersionPair] = []
    if not pairs:
        return selected
    if not by_sev:
        return selected
    quota = max(1, n // max(1, len(by_sev)))
    for sev, bucket in by_sev.items():
        for p in bucket[:quota]:
            selected.append(p)
    rng.shuffle(selected)
    return selected[:n]


def _test_record(pair: VersionPair) -> dict[str, Any]:
    """One held-out test entry. Each pair yields two ground-truth rows.

    The unpatched row is labeled malicious (1), the patched row benign
    (0). Eval arms infer over both rows independently and the runner
    computes confusion matrix per arm.
    """
    advisory = (pair.advisory_ids or [""])[0]
    return {
        "package": pair.package,
        "advisory_id": advisory,
        "severity": pair.severity,
        "unpatched_version": pair.unpatched_version,
        "patched_version": pair.patched_version,
        "ground_truth": {
            pair.unpatched_version: 1,
            pair.patched_version: 0,
        },
        "n_files_changed": len(pair.file_changes),
        "has_install_script_delta": _has_install_script_delta(pair),
        "evidence_paths": [fc.path for fc in pair.file_changes[:10]],
        "package_json_changes": pair.package_json_changes,
    }


def _has_install_script_delta(pair: VersionPair) -> bool:
    before = (pair.package_json_changes or {}).get("before", {}).get("scripts") or {}
    after = (pair.package_json_changes or {}).get("after", {}).get("scripts") or {}
    return any(
        before.get(h) != after.get(h)
        for h in ("preinstall", "install", "postinstall")
    )


def _write_matrix_config(path: Path) -> None:
    """Write the YAML describing the 4-cell matrix.

    We hand-write the YAML rather than depend on PyYAML output formatting
    so the diff against any subsequent revision is reviewable.
    """
    content = (
        "# Apiary 2x2 evaluation matrix.\n"
        "#\n"
        "# axes:\n"
        "#   model: vanilla base | apiary-finetuned LoRA\n"
        "#   inference_style: one-shot | agentic (tool-use)\n"
        "#\n"
        "# Each arm is run against data/eval/matrix-test-set.jsonl. The eval\n"
        "# runner computes verdict accuracy, recall on malicious, false-\n"
        "# positive rate on patched, and average tool-call count for the\n"
        "# agentic arms.\n"
        "\n"
        "schema_version: apiary.eval_matrix.v1\n"
        "test_set: data/eval/matrix-test-set.jsonl\n"
        "\n"
        "arms:\n"
        "  - id: vanilla_oneshot\n"
        "    model: base\n"
        "    model_ref: THUDM/glm-5.1-32b-base\n"
        "    inference_style: oneshot\n"
        "    description: >\n"
        "      Untouched base model, single prompt with the package metadata\n"
        "      and diff. Establishes the floor: how often does an untrained\n"
        "      model get the verdict right when handed all the evidence?\n"
        "\n"
        "  - id: finetuned_oneshot\n"
        "    model: finetuned\n"
        "    model_ref: models/apiary-glm-5.1-32b-base-v1\n"
        "    inference_style: oneshot\n"
        "    description: >\n"
        "      Apiary LoRA adapter, single prompt. Measures the lift from\n"
        "      SFT alone (no tool use).\n"
        "\n"
        "  - id: vanilla_agentic\n"
        "    model: base\n"
        "    model_ref: THUDM/glm-5.1-32b-base\n"
        "    inference_style: agentic\n"
        "    tools: [read_file, list_dir, run_static_analysis]\n"
        "    description: >\n"
        "      Untouched base model with the same tool surface the agentic\n"
        "      SFT data trains. Tests whether tools alone (without the\n"
        "      trajectory training) give a meaningful boost.\n"
        "\n"
        "  - id: finetuned_agentic\n"
        "    model: finetuned\n"
        "    model_ref: models/apiary-glm-5.1-32b-base-v1\n"
        "    inference_style: agentic\n"
        "    tools: [read_file, list_dir, run_static_analysis]\n"
        "    description: >\n"
        "      Apiary LoRA adapter trained on agentic trajectories, with\n"
        "      tools at inference time. The configuration the production\n"
        "      audit backend uses.\n"
        "\n"
        "metrics:\n"
        "  - verdict_accuracy\n"
        "  - malicious_recall\n"
        "  - patched_false_positive_rate\n"
        "  - average_tool_calls   # agentic arms only\n"
        "  - average_latency_seconds\n"
        "  - average_token_cost\n"
    )
    path.write_text(content, encoding="utf-8")


def _write_results_template(path: Path) -> None:
    content = (
        "# Empty scaffold for Andreas's eval runner to populate.\n"
        "schema_version: apiary.eval_matrix.v1\n"
        "matrix_config: data/eval/matrix-config.yaml\n"
        "\n"
        "results:\n"
        "  vanilla_oneshot:\n"
        "    verdict_accuracy: null\n"
        "    malicious_recall: null\n"
        "    patched_false_positive_rate: null\n"
        "    average_latency_seconds: null\n"
        "    average_token_cost: null\n"
        "    notes: \"\"\n"
        "\n"
        "  finetuned_oneshot:\n"
        "    verdict_accuracy: null\n"
        "    malicious_recall: null\n"
        "    patched_false_positive_rate: null\n"
        "    average_latency_seconds: null\n"
        "    average_token_cost: null\n"
        "    notes: \"\"\n"
        "\n"
        "  vanilla_agentic:\n"
        "    verdict_accuracy: null\n"
        "    malicious_recall: null\n"
        "    patched_false_positive_rate: null\n"
        "    average_tool_calls: null\n"
        "    average_latency_seconds: null\n"
        "    average_token_cost: null\n"
        "    notes: \"\"\n"
        "\n"
        "  finetuned_agentic:\n"
        "    verdict_accuracy: null\n"
        "    malicious_recall: null\n"
        "    patched_false_positive_rate: null\n"
        "    average_tool_calls: null\n"
        "    average_latency_seconds: null\n"
        "    average_token_cost: null\n"
        "    notes: \"\"\n"
    )
    path.write_text(content, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version-pairs",
        type=Path,
        default=Path("data/raw/version-pairs/"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/eval/"),
    )
    parser.add_argument(
        "--n-test-cases",
        type=int,
        default=40,
        help="Target size for the held-out test set.",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.version_pairs.is_dir():
        logger.error("version-pairs dir not found: %s", args.version_pairs)
        return 1

    pairs = list(_iter_pairs(args.version_pairs))
    logger.info("loaded %d eligible VersionPairs", len(pairs))
    if not pairs:
        logger.error(
            "no eligible pairs; run scripts/extract_version_pairs.py first"
        )
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)

    sampled = _stratified_sample(pairs, args.n_test_cases, args.seed)
    test_set_path = args.output_dir / "matrix-test-set.jsonl"
    with test_set_path.open("w", encoding="utf-8") as fh:
        for pair in sampled:
            fh.write(json.dumps(_test_record(pair), ensure_ascii=False) + "\n")
    logger.info("wrote %d test cases to %s", len(sampled), test_set_path)

    config_path = args.output_dir / "matrix-config.yaml"
    _write_matrix_config(config_path)
    logger.info("wrote arm config to %s", config_path)

    template_path = args.output_dir / "matrix-results-template.yaml"
    _write_results_template(template_path)
    logger.info("wrote results template to %s", template_path)

    summary = {
        "n_test_cases": len(sampled),
        "n_arms": 4,
        "files": {
            "test_set": str(test_set_path),
            "matrix_config": str(config_path),
            "results_template": str(template_path),
        },
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
