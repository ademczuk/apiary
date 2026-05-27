"""LoRA fine-tune microsoft/codebert-base for npm malicious-package classification.

Inputs:
    data/processed/                  # HF Dataset (train/val/test)

Outputs:
    models/codebert-lora/            # saved adapter + tokenizer + best checkpoint
    runs/codebert/                   # tensorboard logs

LoRA config: r=16, alpha=32, target modules query+value of the RoBERTa attention.

Usage:
    python scripts/train_codebert.py [--epochs 10] [--batch 16] [--out models/codebert-lora]

TODO:
    - Decide on tokenizer max_length (CodeBERT is 512; npm install scripts
      are usually short, but obfuscated JS files can be huge).
    - Add class weights or focal loss if class imbalance bites (expect
      malicious to be ~1% of any real-world stream).
    - Consider freezing all base layers and only training LoRA adapters
      vs. a tiny lr on the base.
    - Wire WandB / TensorBoard for the report.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def build_model(model_name: str = "microsoft/codebert-base"):
    """Load the base model with a classification head and attach LoRA adapters.

    TODO: real implementation:
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        from peft import LoraConfig, get_peft_model, TaskType
        model = AutoModelForSequenceClassification.from_pretrained(
            model_name, num_labels=2
        )
        lora = LoraConfig(
            task_type=TaskType.SEQ_CLS,
            r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            target_modules=["query", "value"],
        )
        model = get_peft_model(model, lora)
        return model, AutoTokenizer.from_pretrained(model_name)
    """
    raise NotImplementedError("Wire transformers + peft here.")


def build_trainer(model, tokenizer, train_ds, val_ds, out_dir: Path, epochs: int, batch: int):
    """Build a HF Trainer with the right TrainingArguments.

    TODO: real implementation:
        from transformers import Trainer, TrainingArguments, DataCollatorWithPadding
        args = TrainingArguments(
            output_dir=str(out_dir),
            num_train_epochs=epochs,
            per_device_train_batch_size=batch,
            per_device_eval_batch_size=batch * 2,
            learning_rate=2e-4,
            warmup_ratio=0.05,
            eval_strategy="steps",
            eval_steps=500,
            save_steps=500,
            save_total_limit=2,
            load_best_model_at_end=True,
            metric_for_best_model="eval_auroc",
            greater_is_better=True,
            fp16=True,
            logging_steps=50,
            report_to=["tensorboard"],
        )
        return Trainer(
            model=model,
            args=args,
            train_dataset=train_ds,
            eval_dataset=val_ds,
            tokenizer=tokenizer,
            data_collator=DataCollatorWithPadding(tokenizer),
            compute_metrics=compute_metrics,
        )
    """
    raise NotImplementedError("Wire Trainer here.")


def compute_metrics(eval_pred):
    """AUROC + PR-AUC + accuracy at threshold 0.5.

    TODO: real implementation uses sklearn.metrics.
    """
    raise NotImplementedError


def load_datasets(processed_dir: Path):
    """Load preprocessed HF Dataset(s) from disk.

    TODO: real implementation:
        from datasets import load_from_disk
        return load_from_disk(processed_dir / "train"), load_from_disk(processed_dir / "val")
    """
    raise NotImplementedError("Wire datasets.load_from_disk here.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed", default="data/processed")
    parser.add_argument("--out", default="models/codebert-lora")
    parser.add_argument("--model", default="microsoft/codebert-base")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch", type=int, default=16)
    parser.add_argument("--dry-run", action="store_true", help="build but do not train")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Model: {args.model}")
    print(f"Output: {out_dir}")
    print(f"Epochs: {args.epochs}  Batch: {args.batch}")

    if args.dry_run:
        print("Dry run; not loading datasets or training.")
        return 0

    # TODO: uncomment when the real implementations land.
    # train_ds, val_ds = load_datasets(Path(args.processed))
    # model, tokenizer = build_model(args.model)
    # trainer = build_trainer(model, tokenizer, train_ds, val_ds, out_dir, args.epochs, args.batch)
    # trainer.train()
    # trainer.save_model(out_dir)
    # tokenizer.save_pretrained(out_dir)

    print("STUB: training loop not yet implemented; see the TODO markers.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
