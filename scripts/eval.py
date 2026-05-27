"""Evaluate a trained model on the test split.

Computes accuracy, precision/recall/F1, AUROC, PR-AUC, confusion matrix at
--threshold, plus split conformal calibration (hand-rolled because mapie's
API for classifiers requires sklearn estimators). Saves metrics.json,
roc_curve.png, pr_curve.png, calibration_plot.png, confusion_matrix.png,
and a per-pattern breakdown when the manifest carries a pattern_id field.

Usage:
    python scripts/eval.py \
        --model models/codebert-lora-v1/ \
        --test-data data/processed/v1/ \
        --output models/codebert-lora-v1/eval/ \
        --threshold 0.30
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

logger = logging.getLogger("apiary.eval")


def _setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _is_codebert_dir(path: Path) -> bool:
    return path.is_dir() and (path / "config.json").exists()


def _is_lightgbm(path: Path) -> bool:
    if path.is_file() and path.suffix in {".json", ".txt"}:
        try:
            with path.open("r", encoding="utf-8") as f:
                head = f.read(200)
            return "tree_info" in head or "version=" in head or "objective=" in head
        except OSError:
            return False
    return False


def load_model(path: Path):
    """Dispatch on model type, return (predict_fn, model_label)."""
    if _is_codebert_dir(path):
        return _load_codebert(path), f"codebert-lora:{path.name}"
    if _is_lightgbm(path):
        return _load_lightgbm(path), f"lightgbm:{path.name}"
    raise ValueError(f"unrecognized model artifact at {path}")


def _load_codebert(path: Path):
    """Return predict_proba(texts: list[str]) -> np.ndarray of positive probs."""
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(str(path))
    model = AutoModelForSequenceClassification.from_pretrained(str(path))
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model = model.to(device).eval()

    @torch.no_grad()
    def predict(texts: list[str], batch_size: int = 16) -> np.ndarray:
        out_probs: list[float] = []
        for start in range(0, len(texts), batch_size):
            batch = texts[start : start + batch_size]
            enc = tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt",
            ).to(device)
            logits = model(**enc).logits.float().cpu().numpy()
            probs = _softmax(logits)[:, 1]
            out_probs.extend(probs.tolist())
        return np.array(out_probs, dtype=np.float64)

    return predict


def _load_lightgbm(path: Path):
    """Return predict(rows: list[dict]) -> probs."""
    import lightgbm as lgb

    booster = lgb.Booster(model_file=str(path))

    meta_path = path.with_suffix(".meta.json")
    if not meta_path.exists():
        raise FileNotFoundError(
            f"missing metadata sidecar: {meta_path} (needed for feature names)"
        )
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    feature_names: list[str] = meta["feature_names"]

    def predict(records: list[dict]) -> np.ndarray:
        X = _featurize_records(records, feature_names)
        return booster.predict(X)

    return predict


def _featurize_records(records: list[dict], feature_names: list[str]) -> np.ndarray:
    """Build the feature matrix using extract_features.extract_row."""
    from scripts.extract_features import extract_row

    rows = []
    for rec in records:
        feats = extract_row(rec)
        rows.append([float(feats.get(c, 0) or 0) for c in feature_names])
    return np.asarray(rows, dtype=np.float32)


def _softmax(x: np.ndarray) -> np.ndarray:
    x = x - x.max(axis=-1, keepdims=True)
    e = np.exp(x)
    return e / e.sum(axis=-1, keepdims=True)


def load_test(test_data: Path) -> list[dict]:
    """Load test records: prefer HF DatasetDict, fall back to JSONL."""
    try:
        from datasets import load_from_disk

        root = test_data / "hf_dataset"
        if (root / "dataset_dict.json").exists():
            dsd = load_from_disk(str(root))
            if "test" in dsd:
                return [dict(row) for row in dsd["test"]]
    except ImportError:
        pass
    jsonl = test_data / "test.jsonl"
    if not jsonl.exists():
        raise FileNotFoundError(f"no test.jsonl under {test_data}")
    rows = []
    with jsonl.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _split_conformal_threshold(
    cal_probs: np.ndarray, cal_labels: np.ndarray, alpha: float = 0.1
) -> float:
    """Hand-rolled split conformal calibration of the decision threshold.

    Uses non-conformity score = 1 - p_y (lower = more conforming). The
    threshold returned is the (1-alpha) empirical quantile of the
    non-conformity scores on the positive class; predictions with
    p_positive >= 1 - threshold are accepted as positive at coverage 1-alpha.
    """
    if len(cal_probs) == 0:
        return float("nan")
    positives = cal_probs[cal_labels == 1]
    if len(positives) == 0:
        return float("nan")
    scores = 1.0 - positives
    q = float(np.quantile(scores, 1 - alpha, method="higher"))
    return 1.0 - q


def _plot_or_skip(fn_name: str):
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        return plt
    except ImportError:
        logger.warning("matplotlib missing; skipping %s plot", fn_name)
        return None


def _plot_roc(y: np.ndarray, probs: np.ndarray, out: Path) -> None:
    plt = _plot_or_skip("roc")
    if plt is None:
        return
    from sklearn.metrics import roc_curve

    fpr, tpr, _ = roc_curve(y, probs)
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot(fpr, tpr, label="ROC")
    ax.plot([0, 1], [0, 1], linestyle="--", color="grey")
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("ROC curve")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def _plot_pr(y: np.ndarray, probs: np.ndarray, out: Path) -> None:
    plt = _plot_or_skip("pr")
    if plt is None:
        return
    from sklearn.metrics import precision_recall_curve

    p, r, _ = precision_recall_curve(y, probs)
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot(r, p)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall curve")
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def _plot_calibration(y: np.ndarray, probs: np.ndarray, out: Path) -> None:
    plt = _plot_or_skip("calibration")
    if plt is None:
        return
    from sklearn.calibration import calibration_curve

    try:
        prob_true, prob_pred = calibration_curve(y, probs, n_bins=10, strategy="quantile")
    except ValueError as exc:
        logger.warning("calibration_curve failed: %s", exc)
        return
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.plot([0, 1], [0, 1], "--", color="grey", label="perfect")
    ax.plot(prob_pred, prob_true, marker="o", label="model")
    ax.set_xlabel("Mean predicted probability")
    ax.set_ylabel("Empirical positive rate")
    ax.set_title("Calibration plot")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def _plot_confusion(cm: np.ndarray, out: Path) -> None:
    plt = _plot_or_skip("confusion")
    if plt is None:
        return
    fig, ax = plt.subplots(figsize=(4, 4))
    im = ax.imshow(cm, cmap="Blues")
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, str(v), ha="center", va="center", color="black")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["pred neg", "pred pos"])
    ax.set_yticklabels(["true neg", "true pos"])
    ax.set_title("Confusion matrix")
    fig.colorbar(im, ax=ax)
    fig.tight_layout()
    fig.savefig(out, dpi=120)
    plt.close(fig)


def _per_pattern_breakdown(
    records: list[dict], probs: np.ndarray, threshold: float
) -> dict:
    """Group records by pattern_id and compute per-bucket accuracy."""
    buckets: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for rec, p in zip(records, probs):
        pid = rec.get("pattern_id")
        if not pid:
            continue
        buckets[pid].append((int(rec.get("label", 0)), float(p)))

    if not buckets:
        return {}

    out: dict[str, dict] = {}
    for pid, items in buckets.items():
        y = np.asarray([t[0] for t in items])
        p = np.asarray([t[1] for t in items])
        preds = (p >= threshold).astype(int)
        out[pid] = {
            "n": int(len(items)),
            "n_pos": int(y.sum()),
            "accuracy": float((preds == y).mean()),
            "mean_score": float(p.mean()),
        }
    return out


def evaluate(predict_fn, records: list[dict], threshold: float) -> dict:
    """Run the prediction function over `records` and compute metrics."""
    from sklearn.metrics import (
        accuracy_score,
        average_precision_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    if not records:
        return {"error": "no records to evaluate", "n_test": 0}

    if "text" in records[0] and isinstance(records[0]["text"], str):
        probs = predict_fn([r.get("text", "") for r in records])
    else:
        probs = predict_fn(records)

    y = np.asarray([int(r.get("label", 0)) for r in records])
    preds = (probs >= threshold).astype(int)

    metrics: dict = {
        "n_test": int(len(y)),
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(y, preds)),
        "precision": float(precision_score(y, preds, zero_division=0)),
        "recall": float(recall_score(y, preds, zero_division=0)),
        "f1": float(f1_score(y, preds, zero_division=0)),
        "confusion": confusion_matrix(y, preds, labels=[0, 1]).tolist(),
        "label_distribution": {
            "negative": int((y == 0).sum()),
            "positive": int((y == 1).sum()),
        },
    }
    if len(np.unique(y)) > 1:
        metrics["auroc"] = float(roc_auc_score(y, probs))
        metrics["pr_auc"] = float(average_precision_score(y, probs))
    else:
        metrics["auroc"] = float("nan")
        metrics["pr_auc"] = float("nan")

    # Split conformal at alpha=0.1: use first half as calibration set
    half = max(1, len(records) // 2)
    cal_probs = probs[:half]
    cal_y = y[:half]
    metrics["conformal_threshold_alpha_0.1"] = _split_conformal_threshold(
        cal_probs, cal_y, alpha=0.1
    )

    metrics["per_pattern"] = _per_pattern_breakdown(records, probs, threshold)
    return metrics, probs, y


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--test-data", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--threshold", type=float, default=0.30)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    _setup_logging(args.verbose)
    out_dir: Path = args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    predict_fn, model_label = load_model(args.model)
    test_records = load_test(args.test_data)
    logger.info("loaded %d test records (model=%s)", len(test_records), model_label)

    metrics, probs, y = evaluate(predict_fn, test_records, args.threshold)
    metrics["model"] = model_label

    # Plots
    if len(np.unique(y)) > 1:
        _plot_roc(y, probs, out_dir / "roc_curve.png")
        _plot_pr(y, probs, out_dir / "pr_curve.png")
        _plot_calibration(y, probs, out_dir / "calibration_plot.png")
    cm = np.asarray(metrics["confusion"])
    _plot_confusion(cm, out_dir / "confusion_matrix.png")

    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    logger.info("wrote metrics: %s", out_dir / "metrics.json")
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
