"""Eval the fine-tuned apiary auditor on the held-out test split.

Reports verdict accuracy, binary F1 / AUROC, refusal rate, and latency
percentiles. Outputs a metrics JSON in ``<model>/eval/metrics.json``.
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import statistics
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

logger = logging.getLogger("apiary.eval")

REFUSAL_PATTERNS = (
    r"\bI cannot\b",
    r"\bI can't\b",
    r"\bI'm sorry\b",
    r"\bI am sorry\b",
    r"\bI cannot help\b",
    r"\bI am not able\b",
    r"\bI won't\b",
    r"\bI will not\b",
    r"\bagainst my\b",
    r"\bnot appropriate\b",
    r"\bunable to assist\b",
)
_REFUSAL_RE = re.compile("|".join(REFUSAL_PATTERNS), re.IGNORECASE)
_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


@dataclass
class EvalRecord:
    package: str
    label: str
    prompt: str
    expected_assistant: str


def _require(module: str) -> Any:
    try:
        return __import__(module, fromlist=["*"])
    except ImportError as exc:
        raise RuntimeError(f"{module} is required for eval") from exc


def _load_eval_records(path: Path) -> list[EvalRecord]:
    rows: list[EvalRecord] = []
    with Path(path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            messages = rec.get("messages") or []
            meta = rec.get("meta") or {}
            if len(messages) < 3:
                continue
            system_prompt = messages[0]["content"]
            user_prompt = messages[1]["content"]
            expected = messages[2]["content"]
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            rows.append(
                EvalRecord(
                    package=str(meta.get("package", "unknown")),
                    label=str(meta.get("label", "suspicious")),
                    prompt=full_prompt,
                    expected_assistant=expected,
                )
            )
    logger.info("loaded %d eval records from %s", len(rows), path)
    return rows


def _parse_verdict(raw: str) -> tuple[str, float, bool]:
    """Extract (verdict, confidence, was_refusal) from raw model output."""
    is_refusal = bool(_REFUSAL_RE.search(raw or ""))
    match = _JSON_OBJECT_RE.search(raw or "")
    if not match:
        return "suspicious", 0.0, is_refusal
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError:
        return "suspicious", 0.0, is_refusal
    verdict = str(payload.get("verdict", "suspicious")).lower().strip()
    if verdict not in ("clean", "suspicious", "malicious"):
        verdict = "suspicious"
    try:
        confidence = float(payload.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    return verdict, max(0.0, min(1.0, confidence)), is_refusal


def _load_model_for_inference(model_path: str, base_model: str | None = None) -> tuple[Any, Any]:
    torch = _require("torch")
    transformers = _require("transformers")
    AutoTokenizer = transformers.AutoTokenizer
    AutoModelForCausalLM = transformers.AutoModelForCausalLM

    adapter_dir = Path(model_path)
    is_adapter = (adapter_dir / "adapter_config.json").exists()
    tokenizer_source = base_model if (is_adapter and base_model) else model_path
    tokenizer = AutoTokenizer.from_pretrained(tokenizer_source, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    if is_adapter:
        peft = _require("peft")
        if not base_model:
            raise ValueError("loading a LoRA adapter requires --base-model")
        base = AutoModelForCausalLM.from_pretrained(
            base_model,
            torch_dtype=torch.bfloat16,
            device_map="auto",
            trust_remote_code=True,
        )
        model = peft.PeftModel.from_pretrained(base, model_path)
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_path,
            torch_dtype=torch.bfloat16,
            device_map="auto",
            trust_remote_code=True,
        )
    model.eval()
    return model, tokenizer


def _generate(model: Any, tokenizer: Any, prompt: str, max_new_tokens: int = 512) -> tuple[str, float]:
    torch = _require("torch")
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=8192).to(model.device)
    start = time.perf_counter()
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=1.0,
            pad_token_id=tokenizer.pad_token_id,
        )
    duration = time.perf_counter() - start
    new_tokens = out[0][inputs["input_ids"].shape[1]:]
    text = tokenizer.decode(new_tokens, skip_special_tokens=True)
    return text, duration


def _binary_f1(y_true: list[int], y_pred: list[int]) -> dict[str, float]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1}


def _auroc(y_true: list[int], scores: list[float]) -> float:
    """Mann-Whitney U based AUROC (no sklearn dep)."""
    pairs = sorted(zip(scores, y_true), key=lambda kv: kv[0])
    pos = [i for i, (_, y) in enumerate(pairs, start=1) if y == 1]
    n_pos = sum(y_true)
    n_neg = len(y_true) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.5
    rank_sum = sum(pos)
    auroc = (rank_sum - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)
    return float(auroc)


def evaluate(
    model_path: str,
    test_data: Path,
    output_dir: Path,
    base_model: str | None = None,
    max_records: int | None = None,
    max_new_tokens: int = 512,
) -> dict[str, Any]:
    """Run eval and return the metrics dict (also written to disk)."""
    records = _load_eval_records(test_data)
    if max_records is not None:
        records = records[:max_records]

    model, tokenizer = _load_model_for_inference(model_path, base_model=base_model)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    predictions: list[dict[str, Any]] = []
    latencies: list[float] = []
    refusal_count = 0
    correct = 0
    y_true_bin: list[int] = []
    y_pred_bin: list[int] = []
    scores: list[float] = []
    by_label: Counter[str] = Counter()
    by_correct: Counter[str] = Counter()

    for idx, rec in enumerate(records):
        raw, duration = _generate(model, tokenizer, rec.prompt, max_new_tokens=max_new_tokens)
        verdict, confidence, is_refusal = _parse_verdict(raw)
        latencies.append(duration)
        if is_refusal:
            refusal_count += 1
        is_correct = verdict == rec.label
        if is_correct:
            correct += 1
            by_correct[rec.label] += 1
        by_label[rec.label] += 1
        # binary collapse: malicious vs not-malicious
        y_true_bin.append(1 if rec.label == "malicious" else 0)
        y_pred_bin.append(1 if verdict == "malicious" else 0)
        scores.append(confidence if verdict == "malicious" else 1.0 - confidence)
        predictions.append(
            {
                "package": rec.package,
                "expected": rec.label,
                "predicted": verdict,
                "confidence": confidence,
                "refusal": is_refusal,
                "latency_s": duration,
                "raw_truncated": (raw or "")[:200],
            }
        )
        if (idx + 1) % 20 == 0:
            logger.info("processed %d/%d", idx + 1, len(records))

    n = max(1, len(records))
    binary = _binary_f1(y_true_bin, y_pred_bin)
    auroc = _auroc(y_true_bin, scores)
    per_label_acc = {
        label: (by_correct[label] / by_label[label]) if by_label[label] else 0.0
        for label in by_label
    }
    latencies_sorted = sorted(latencies) or [0.0]
    metrics = {
        "model": model_path,
        "base_model": base_model,
        "test_data": str(test_data),
        "n_records": len(records),
        "verdict_accuracy": correct / n,
        "binary": binary,
        "auroc": auroc,
        "refusal_rate": refusal_count / n,
        "per_label_accuracy": per_label_acc,
        "label_distribution": dict(by_label),
        "latency_s": {
            "mean": statistics.mean(latencies) if latencies else 0.0,
            "p50": latencies_sorted[len(latencies_sorted) // 2],
            "p95": latencies_sorted[int(len(latencies_sorted) * 0.95)] if latencies_sorted else 0.0,
            "max": max(latencies) if latencies else 0.0,
        },
        "tokens_per_second_estimate": (n * max_new_tokens) / sum(latencies) if sum(latencies) else 0.0,
    }
    (output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (output_dir / "predictions.jsonl").write_text(
        "\n".join(json.dumps(p, ensure_ascii=False) for p in predictions),
        encoding="utf-8",
    )
    logger.info(
        "verdict_accuracy=%.3f  binary_f1=%.3f  auroc=%.3f  refusal_rate=%.3f",
        metrics["verdict_accuracy"],
        binary["f1"],
        auroc,
        metrics["refusal_rate"],
    )
    return metrics


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Apiary fine-tuned auditor eval")
    p.add_argument("--model", required=True, help="Adapter or full model dir")
    p.add_argument("--base-model", default=None, help="Required when --model is a LoRA adapter")
    p.add_argument("--test-data", required=True, type=Path)
    p.add_argument("--output", type=Path, default=None, help="Defaults to <model>/eval")
    p.add_argument("--max-records", type=int, default=None)
    p.add_argument("--max-new-tokens", type=int, default=512)
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    output_dir = args.output or (Path(args.model) / "eval")
    metrics = evaluate(
        model_path=args.model,
        test_data=args.test_data,
        output_dir=output_dir,
        base_model=args.base_model,
        max_records=args.max_records,
        max_new_tokens=args.max_new_tokens,
    )
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
