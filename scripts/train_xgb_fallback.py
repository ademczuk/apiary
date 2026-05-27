"""Train the LightGBM fallback classifier on hand-crafted features.

5-fold stratified CV with LightGBM defaults. Reports per-fold AUROC,
PR-AUC, and F1 at threshold 0.5. Saves the final booster (trained on full
data) plus a metadata JSON for downstream consumption by score_package.py.

Usage:
    python scripts/train_xgb_fallback.py \
        --features data/processed/v1/features.parquet \
        --output models/xgb-fallback-v1.json \
        --seed 42
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np

logger = logging.getLogger("apiary.train_fallback")

EXCLUDE_COLS = {
    "package_name",
    "version",
    "ecosystem",
    "source",
    "label",
    "split",
}


def _setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def load_features(path: Path) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Load parquet (or JSONL twin) into X, y, feature_names."""
    try:
        import pandas as pd
    except ImportError as exc:
        raise RuntimeError("pandas is required to load features") from exc

    if path.exists() and path.suffix == ".parquet":
        df = pd.read_parquet(path)
    else:
        twin = path.with_suffix(".jsonl")
        if not twin.exists():
            raise FileNotFoundError(f"no features file at {path} or {twin}")
        df = pd.read_json(twin, lines=True)

    feat_cols = [c for c in df.columns if c not in EXCLUDE_COLS]
    # Coerce booleans to int, fill NaN with column median or 0.
    for col in feat_cols:
        if df[col].dtype == bool:
            df[col] = df[col].astype(int)
        if df[col].isna().any():
            fill = df[col].median() if df[col].notna().any() else 0
            df[col] = df[col].fillna(fill)

    X = df[feat_cols].to_numpy(dtype=np.float32)
    y = df["label"].astype(int).to_numpy()
    return X, y, feat_cols


def _train_lightgbm(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray | None,
    y_val: np.ndarray | None,
    seed: int,
):
    """Fit a LightGBM classifier with sane defaults. Returns the booster."""
    import lightgbm as lgb

    params = {
        "objective": "binary",
        "metric": "auc",
        "learning_rate": 0.05,
        "num_leaves": 63,
        "max_depth": -1,
        "min_data_in_leaf": 20,
        "feature_fraction": 0.9,
        "bagging_fraction": 0.9,
        "bagging_freq": 5,
        "verbose": -1,
        "seed": seed,
    }
    train_set = lgb.Dataset(X_train, label=y_train)
    valid_sets = [train_set]
    valid_names = ["train"]
    if X_val is not None and y_val is not None:
        valid_sets.append(lgb.Dataset(X_val, label=y_val, reference=train_set))
        valid_names.append("val")

    callbacks = [lgb.early_stopping(stopping_rounds=50, verbose=False)] if X_val is not None else []
    booster = lgb.train(
        params,
        train_set,
        num_boost_round=500,
        valid_sets=valid_sets,
        valid_names=valid_names,
        callbacks=callbacks,
    )
    return booster


def _cv_evaluate(
    X: np.ndarray, y: np.ndarray, feature_names: list[str], seed: int, n_splits: int = 5
) -> list[dict]:
    """Run k-fold stratified CV and return per-fold metric dicts."""
    from sklearn.metrics import (
        average_precision_score,
        f1_score,
        roc_auc_score,
    )
    from sklearn.model_selection import StratifiedKFold

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    fold_metrics: list[dict] = []

    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X, y)):
        X_tr, X_va = X[train_idx], X[val_idx]
        y_tr, y_va = y[train_idx], y[val_idx]

        booster = _train_lightgbm(X_tr, y_tr, X_va, y_va, seed)
        probs = booster.predict(X_va)
        preds = (probs >= 0.5).astype(int)

        # AUROC / PR-AUC need at least one positive and one negative
        if len(np.unique(y_va)) < 2:
            auroc = float("nan")
            pr_auc = float("nan")
        else:
            auroc = float(roc_auc_score(y_va, probs))
            pr_auc = float(average_precision_score(y_va, probs))

        f1 = float(f1_score(y_va, preds, zero_division=0))

        fold_metrics.append(
            {
                "fold": fold_idx,
                "n_train": int(len(train_idx)),
                "n_val": int(len(val_idx)),
                "auroc": auroc,
                "pr_auc": pr_auc,
                "f1_at_0.5": f1,
                "n_pos_val": int(y_va.sum()),
                "n_neg_val": int((1 - y_va).sum()),
            }
        )
        logger.info(
            "fold %d: AUROC=%.4f PR-AUC=%.4f F1=%.4f (n_val=%d)",
            fold_idx,
            auroc,
            pr_auc,
            f1,
            len(val_idx),
        )

    return fold_metrics


def _aggregate_metrics(fold_metrics: list[dict]) -> dict:
    aurocs = [f["auroc"] for f in fold_metrics if not np.isnan(f["auroc"])]
    pr_aucs = [f["pr_auc"] for f in fold_metrics if not np.isnan(f["pr_auc"])]
    f1s = [f["f1_at_0.5"] for f in fold_metrics]
    return {
        "mean_auroc": float(np.mean(aurocs)) if aurocs else float("nan"),
        "std_auroc": float(np.std(aurocs)) if aurocs else float("nan"),
        "mean_pr_auc": float(np.mean(pr_aucs)) if pr_aucs else float("nan"),
        "std_pr_auc": float(np.std(pr_aucs)) if pr_aucs else float("nan"),
        "mean_f1": float(np.mean(f1s)) if f1s else float("nan"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--cv-folds", type=int, default=5)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    _setup_logging(args.verbose)

    out_path: Path = args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        import lightgbm as lgb  # noqa: F401
    except ImportError:
        logger.error("lightgbm is required: `pip install lightgbm`")
        return 1

    X, y, feature_names = load_features(args.features)
    logger.info(
        "loaded %d rows, %d features, %d positive (%.1f%%)",
        len(X),
        len(feature_names),
        int(y.sum()),
        100.0 * y.sum() / max(1, len(y)),
    )

    if len(np.unique(y)) < 2:
        logger.error("dataset has only one class; cannot train classifier")
        return 1

    fold_metrics = _cv_evaluate(X, y, feature_names, args.seed, args.cv_folds)
    agg = _aggregate_metrics(fold_metrics)
    logger.info(
        "CV summary: AUROC=%.4f+/-%.4f PR-AUC=%.4f+/-%.4f",
        agg["mean_auroc"],
        agg["std_auroc"],
        agg["mean_pr_auc"],
        agg["std_pr_auc"],
    )

    # Final fit on all data
    logger.info("training final model on full data (%d rows)", len(X))
    final_booster = _train_lightgbm(X, y, None, None, args.seed)
    final_booster.save_model(str(out_path))
    logger.info("saved model: %s", out_path)

    meta_path = out_path.with_suffix(".meta.json")
    meta = {
        "model_type": "lightgbm",
        "feature_names": feature_names,
        "n_train_rows": int(len(X)),
        "label_positive_rate": float(y.sum() / max(1, len(y))),
        "seed": args.seed,
        "cv_folds": args.cv_folds,
        "fold_metrics": fold_metrics,
        "cv_summary": agg,
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    logger.info("wrote metadata: %s", meta_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
