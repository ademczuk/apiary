#!/bin/bash
#SBATCH --job-name=apiary-codebert
#SBATCH --partition=boost_usr_prod
#SBATCH --account=YOUR_ACCOUNT_HERE
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=32
#SBATCH --gres=gpu:4
#SBATCH --mem=480G
#SBATCH --time=08:00:00
#SBATCH --output=runs/slurm/%x-%j.out
#SBATCH --error=runs/slurm/%x-%j.err
#
# Leonardo (CINECA) submission for the CodeBERT LoRA fine-tune.
# 4x A100 (64 GB), 8 hours wall clock, 32 CPU cores, 480 GB RAM.
#
# Submit:
#     sbatch slurm/train.slurm
#
# Adjust --account before submission; CINECA jobs require a valid project ID.
# The boost_usr_prod partition is the standard production GPU queue on Leonardo
# Booster; confirm with `sinfo` if it has been renamed in the meantime.

set -euo pipefail

mkdir -p runs/slurm

module purge
module load profile/deeplrn
module load cuda/12.1
module load python/3.11.7
module load gcc/12.2.0

# Activate the project venv (uv-managed)
source .venv/bin/activate

export TOKENIZERS_PARALLELISM=false
export OMP_NUM_THREADS=8
export HF_HOME=$SCRATCH/hf_cache
export TRANSFORMERS_CACHE=$SCRATCH/hf_cache
mkdir -p "$HF_HOME"

# Use torchrun to scale across the 4 GPUs.
# Effective batch size = per_device_batch * n_gpus * grad_accum.
torchrun \
    --standalone \
    --nproc_per_node=4 \
    scripts/train_codebert.py \
        --train-data data/processed \
        --output models/codebert-lora \
        --base-model microsoft/codebert-base \
        --epochs 10 \
        --batch-size 16

echo "Done at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
