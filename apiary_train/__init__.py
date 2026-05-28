"""Apiary v3 training stack.

Pipeline for the production audit model:

1. ``apiary_train.abliteration`` removes refusal-cascade behavior from a base
   model via Failspy's refusal-direction orthogonalization technique
   (Arditi et al., 2024, https://arxiv.org/abs/2406.11717).
2. ``apiary_train.data_prep`` converts the figshare NPM Malicious Package
   Study + the synthetic 22-pattern attack catalog into instruction-tuning
   JSONL pairs.
3. ``apiary_train.sft_lora`` runs LoRA SFT via ``trl.SFTTrainer`` + ``peft``,
   wired for multi-node FSDP across 64 H100s.
4. ``apiary_train.eval`` scores the fine-tuned model on a held-out split:
   verdict accuracy, F1, AUROC, refusal rate, latency.
5. ``apiary_train.rehearsal`` runs the full pipeline against a 1.5B model in
   about thirty minutes on one GPU so the workflow can be validated before
   the H100 burn.

The trained adapter is consumed in production by
``apiary_auditors.llm_audit.ApiaryFineTunedBackend``.
"""

from __future__ import annotations

__version__ = "0.3.0"

__all__ = [
    "__version__",
]
