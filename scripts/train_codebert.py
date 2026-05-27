"""LoRA fine-tune of microsoft/codebert-base for npm package classification.

Loads a HuggingFace DatasetDict from --train-data (must contain train + val
splits), attaches a LoRA adapter (target modules: query, value), trains via
the HF Trainer, and saves the best checkpoint by val AUROC. Logs to wandb
when available; gracefully degrades to stdout otherwise. Honors
WANDB_DISABLED=true.

Usage:
    python scripts/train_codebert.py \
        --train-data data/processed/v1/ \
        --output models/codebert-lora-v1/ \
        --base-model microsoft/codebert-base \
        --batch-size 32 --epochs 5 --lr 2e-5 \
        --lora-r 16 --lora-alpha 32 \
        --eval-steps 500 --save-steps 500 \
        --seed 42 --report-to wandb
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

import numpy as np

logger = logging.getLogger("apiary.train_codebert")


def _setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _resolve_dataset_dir(train_data: Path) -> Path:
    """Find a saved HF DatasetDict under `train_data`."""
    candidates = [train_data, train_data / "hf_dataset"]
    for c in candidates:
        if (c / "dataset_dict.json").exists():
            return c
    # Last resort: assume `train_data` itself is the DatasetDict root
    return train_data


def load_datasets(train_data: Path):
    """Load DatasetDict from disk, falling back to JSONL if needed."""
    from datasets import Dataset, DatasetDict, load_from_disk

    root = _resolve_dataset_dir(train_data)
    if (root / "dataset_dict.json").exists():
        dsd = load_from_disk(str(root))
        if "train" not in dsd:
            raise ValueError(f"DatasetDict at {root} has no `train` split")
        if "val" not in dsd:
            raise ValueError(f"DatasetDict at {root} has no `val` split")
        return dsd

    # JSONL fallback (manifest output)
    logger.warning("no saved DatasetDict; loading JSONL splits from %s", train_data)
    splits: dict = {}
    for split in ("train", "val", "test"):
        path = train_data / f"{split}.jsonl"
        if path.exists():
            splits[split] = Dataset.from_json(str(path))
    if "train" not in splits or "val" not in splits:
        raise FileNotFoundError(f"missing train/val JSONL in {train_data}")
    return DatasetDict(splits)


def build_model(
    base_model: str,
    lora_r: int,
    lora_alpha: int,
    lora_dropout: float,
):
    """Load CodeBERT with a binary classification head and attach LoRA adapters."""
    from peft import LoraConfig, TaskType, get_peft_model
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(base_model)
    model = AutoModelForSequenceClassification.from_pretrained(
        base_model, num_labels=2
    )
    lora_cfg = LoraConfig(
        task_type=TaskType.SEQ_CLS,
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        bias="none",
        target_modules=["query", "value"],
    )
    model = get_peft_model(model, lora_cfg)
    try:
        model.print_trainable_parameters()
    except Exception:  # noqa: BLE001
        pass
    return model, tokenizer


def tokenize_datasets(dsd, tokenizer, max_length: int):
    """Tokenize text fields and align label column."""
    text_col = "text"
    if text_col not in dsd["train"].column_names:
        raise KeyError(
            f"train split is missing `{text_col}` column; got "
            f"{dsd['train'].column_names}"
        )

    def _tok(batch):
        return tokenizer(
            batch[text_col],
            padding=False,
            truncation=True,
            max_length=max_length,
        )

    keep = {"label"}
    for split_name in list(dsd.keys()):
        ds = dsd[split_name]
        drop = [c for c in ds.column_names if c not in keep and c != text_col]
        ds = ds.map(_tok, batched=True, remove_columns=drop + [text_col])
        ds = ds.rename_column("label", "labels") if "label" in ds.column_names else ds
        dsd[split_name] = ds
    return dsd


def compute_metrics(eval_pred):
    """accuracy + precision + recall + F1 + AUROC at threshold 0.5."""
    from sklearn.metrics import (
        accuracy_score,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    logits, labels = eval_pred
    if isinstance(logits, tuple):
        logits = logits[0]
    probs = _softmax(logits)[:, 1]
    preds = probs >= 0.5
    out = {
        "accuracy": float(accuracy_score(labels, preds)),
        "precision": float(precision_score(labels, preds, zero_division=0)),
        "recall": float(recall_score(labels, preds, zero_division=0)),
        "f1": float(f1_score(labels, preds, zero_division=0)),
    }
    if len(np.unique(labels)) > 1:
        out["auroc"] = float(roc_auc_score(labels, probs))
    else:
        out["auroc"] = float("nan")
    return out


def _softmax(x: np.ndarray) -> np.ndarray:
    x = x - x.max(axis=-1, keepdims=True)
    e = np.exp(x)
    return e / e.sum(axis=-1, keepdims=True)


def _detect_report_to(requested: str) -> list[str]:
    """Decide reporters: respect WANDB_DISABLED and missing wandb install."""
    requested = (requested or "none").lower()
    if requested in {"none", "off", "false"}:
        return []
    if os.environ.get("WANDB_DISABLED", "").lower() in {"true", "1", "yes"}:
        logger.info("WANDB_DISABLED set; not reporting to wandb")
        return []
    if requested == "wandb":
        try:
            import wandb  # noqa: F401

            return ["wandb"]
        except ImportError:
            logger.warning("wandb not installed; falling back to stdout-only logs")
            return []
    return [requested]


def build_trainer(
    model,
    tokenizer,
    train_ds,
    val_ds,
    output_dir: Path,
    args,
):
    from transformers import (
        DataCollatorWithPadding,
        Trainer,
        TrainingArguments,
    )

    fp16 = bool(getattr(args, "fp16", True))
    try:
        import torch

        if not torch.cuda.is_available():
            fp16 = False
    except ImportError:
        fp16 = False

    report_to = _detect_report_to(args.report_to)

    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=max(1, args.batch_size * 2),
        learning_rate=args.lr,
        warmup_ratio=0.05,
        eval_strategy="steps",
        eval_steps=args.eval_steps,
        save_steps=args.save_steps,
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="auroc",
        greater_is_better=True,
        fp16=fp16,
        logging_steps=50,
        report_to=report_to,
        seed=args.seed,
        dataloader_num_workers=2,
    )

    return Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-data", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--base-model", default="microsoft/codebert-base")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--lora-r", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--eval-steps", type=int, default=500)
    parser.add_argument("--save-steps", type=int, default=500)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--report-to", default="wandb")
    parser.add_argument("--fp16", action="store_true", default=True)
    parser.add_argument("--no-fp16", dest="fp16", action="store_false")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    _setup_logging(args.verbose)
    out_dir: Path = args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        import transformers  # noqa: F401
        import peft  # noqa: F401
        import datasets  # noqa: F401
    except ImportError as exc:
        logger.error("missing dependency: %s. Install transformers/peft/datasets.", exc)
        return 1

    logger.info("base model: %s", args.base_model)
    logger.info("output: %s", out_dir)
    logger.info("epochs=%d batch=%d lr=%g", args.epochs, args.batch_size, args.lr)

    dsd = load_datasets(args.train_data)
    logger.info(
        "loaded splits: train=%d val=%d test=%d",
        len(dsd["train"]),
        len(dsd["val"]),
        len(dsd.get("test", [])) if "test" in dsd else 0,
    )

    model, tokenizer = build_model(
        args.base_model,
        args.lora_r,
        args.lora_alpha,
        args.lora_dropout,
    )
    dsd = tokenize_datasets(dsd, tokenizer, args.max_length)

    trainer = build_trainer(
        model,
        tokenizer,
        dsd["train"],
        dsd["val"],
        out_dir,
        args,
    )

    if args.dry_run:
        logger.info("dry-run: skipping trainer.train()")
        return 0

    train_result = trainer.train()
    trainer.save_model(str(out_dir))
    tokenizer.save_pretrained(str(out_dir))

    train_metrics = dict(train_result.metrics) if hasattr(train_result, "metrics") else {}
    eval_metrics = trainer.evaluate()
    (out_dir / "train_metrics.json").write_text(json.dumps(train_metrics, indent=2))
    (out_dir / "eval_metrics.json").write_text(json.dumps(eval_metrics, indent=2))
    logger.info("eval metrics: %s", json.dumps(eval_metrics, indent=2))
    logger.info("saved model to %s", out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
