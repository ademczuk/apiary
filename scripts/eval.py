"""Evaluate a trained model (CodeBERT LoRA or xgb fallback) on the test split.

Reports:
    AUROC
    PR-AUC
    Confusion matrix at the chosen threshold
    Calibration table (predicted probability vs empirical positive rate)
    Conformal interval at 95% via MAPIE

Inputs:
    models/codebert-lora/   OR   models/xgb-fallback.pkl
    data/processed/test.jsonl

Outputs:
    runs/eval/<model>/metrics.json
    runs/eval/<model>/confusion.png
    runs/eval/<model>/calibration.png

Usage:
    python scripts/eval.py --model models/xgb-fallback.pkl --threshold 0.30

TODO:
    - Build the confusion-matrix and calibration plots with matplotlib.
    - Hook MAPIE for conformal calibration on the val split, then evaluate
      coverage on test.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_model(path: Path):
    """Load either a CodeBERT model directory or an xgboost pickle.

    TODO: dispatch on path.is_dir() vs path.suffix; load with the right loader.
    """
    raise NotImplementedError


def load_test(processed_dir: Path):
    """Load the held-out test split.

    TODO: load_from_disk(processed_dir / 'test').
    """
    raise NotImplementedError


def evaluate(model, test_ds, threshold: float) -> dict:
    """Run model over test, compute metrics, return a dict suitable for JSON dump.

    TODO: real implementation:
        from sklearn.metrics import roc_auc_score, average_precision_score, confusion_matrix
        probs = predict_proba(model, test_ds)
        y = [r["label"] for r in test_ds]
        return {
            "auroc": roc_auc_score(y, probs),
            "pr_auc": average_precision_score(y, probs),
            "confusion": confusion_matrix(y, [int(p >= threshold) for p in probs]).tolist(),
            "threshold": threshold,
            "n_test": len(y),
        }
    """
    return {
        "auroc": None,
        "pr_auc": None,
        "confusion": [[0, 0], [0, 0]],
        "threshold": threshold,
        "n_test": 0,
        "stub": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--processed", default="data/processed")
    parser.add_argument("--threshold", type=float, default=0.30)
    parser.add_argument("--out", default="runs/eval")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    out_dir = Path(args.out) / Path(args.model).stem
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.dry_run:
        metrics = {"stub": True}
    else:
        # TODO: uncomment when load_model / load_test work
        # model = load_model(Path(args.model))
        # test_ds = load_test(Path(args.processed))
        # metrics = evaluate(model, test_ds, args.threshold)
        metrics = evaluate(None, None, args.threshold)

    metrics_path = out_dir / "metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2))
    print(f"WROTE: {metrics_path}")
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
