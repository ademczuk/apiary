"""Train the gradient-booster fallback classifier.

This model exists for three reasons:
    1. The CodeBERT LoRA fine-tune takes hours on a single A100; the
       fallback trains in under a minute on CPU.
    2. When CodeBERT is unavailable (no GPU on the gate host, model
       still downloading, package larger than 512 tokens), the gate
       must still return a verdict.
    3. The feature importances are an interpretability handle for the
       evidence field on each verdict.

Inputs:
    data/interim/features.parquet   # output of scripts/extract_features.py

Outputs:
    models/xgb-fallback.pkl         # joblib-serialized booster + feature list

Usage:
    python scripts/train_xgb_fallback.py [--in data/interim/features.parquet] [--out models/xgb-fallback.pkl]

TODO:
    - Plug in xgboost.XGBClassifier with sensible defaults.
    - Add the conformal calibration wrap via MAPIE so the gate gets
      proper confidence bounds.
    - Persist feature names alongside the model so score_package.py
      can vectorize new inputs identically.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_features(path: Path):
    """Load the parquet or JSONL feature table into a numpy X, y, feature_names triple.

    TODO: real implementation:
        import pandas as pd
        df = pd.read_parquet(path) if path.suffix == ".parquet" else pd.read_json(path, lines=True)
        feat_cols = [c for c in df.columns if c not in {"label", "package_name", "version", "ecosystem", "split"}]
        X = df[feat_cols].values
        y = df["label"].values
        return X, y, feat_cols, df["split"].values
    """
    # Minimal JSONL fallback so the script runs even without pandas/pyarrow
    rows: list[dict] = []
    if not path.exists():
        # Try the JSONL twin
        jsonl = path.with_suffix(".jsonl")
        if jsonl.exists():
            path = jsonl
        else:
            return [], [], [], []
    with path.open(encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if not rows:
        return [], [], [], []

    skip = {"label", "package_name", "version", "ecosystem", "split"}
    feat_cols = [k for k in rows[0].keys() if k not in skip]
    X = [[r.get(c, 0) for c in feat_cols] for r in rows]
    y = [r.get("label", 0) for r in rows]
    splits = [r.get("split", "train") for r in rows]
    return X, y, feat_cols, splits


def train(X, y, feature_names):
    """Train xgboost.XGBClassifier and return a fitted booster.

    TODO: real implementation:
        from xgboost import XGBClassifier
        clf = XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="auc",
            n_jobs=-1,
            tree_method="hist",
        )
        clf.fit(X, y)
        return clf
    """
    raise NotImplementedError("Wire xgboost here once features.parquet is real.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="in_path", default="data/interim/features.parquet")
    parser.add_argument("--out", default="models/xgb-fallback.pkl")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    X, y, feature_names, splits = load_features(in_path)
    print(f"Loaded {len(X)} rows, {len(feature_names)} features")

    if not X or args.dry_run:
        print("STUB: nothing to train (no rows) or --dry-run set.")
        return 0

    # TODO: split into train/val using the precomputed split column.
    # TODO: train, evaluate, conformal-calibrate, persist.
    # clf = train(X, y, feature_names)
    # joblib.dump({"model": clf, "features": feature_names}, out_path)
    # print(f"WROTE: {out_path}")

    print("STUB: training not yet implemented; see TODO markers.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
