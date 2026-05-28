#!/bin/bash
#SBATCH --job-name=apiary-train-v3
#SBATCH --partition=h100
#SBATCH --account=YOUR_ACCOUNT_HERE
#SBATCH --nodes=8
#SBATCH --ntasks-per-node=8
#SBATCH --gpus-per-node=8
#SBATCH --cpus-per-task=16
#SBATCH --mem=0
#SBATCH --time=12:00:00
#SBATCH --output=runs/slurm/%x-%j.out
#SBATCH --error=runs/slurm/%x-%j.err
#
# Apiary v3 training pipeline on a 64x H100 cluster.
# Three stages: abliteration (1 node), SFT LoRA (8 nodes FSDP), eval (1 node).
#
# Submit:
#     sbatch slurm/abliterate_then_sft.slurm
#
# Override the base model:
#     BASE_MODEL=THUDM/glm-5.1-32b-base sbatch slurm/abliterate_then_sft.slurm
#     BASE_MODEL=deepseek-ai/DeepSeek-V4-Pro-Base sbatch slurm/abliterate_then_sft.slurm

set -euo pipefail

mkdir -p runs/slurm models

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

module purge
module load profile/deeplrn 2>/dev/null || true
module load cuda/12.4 2>/dev/null || true
module load python/3.11 2>/dev/null || true
module load gcc/12.2 2>/dev/null || true

source .venv/bin/activate

export TOKENIZERS_PARALLELISM=false
export OMP_NUM_THREADS=8
export HF_HOME="${SCRATCH:-$HOME/scratch}/hf_cache"
export TRANSFORMERS_CACHE="$HF_HOME"
export NCCL_DEBUG=WARN
export NCCL_ASYNC_ERROR_HANDLING=1
mkdir -p "$HF_HOME"

BASE_MODEL="${BASE_MODEL:-THUDM/glm-5.1-32b-base}"
MODEL_TAG="$(basename "$BASE_MODEL")"
ABLITERATED_DIR="models/${MODEL_TAG}-abliterated"
SFT_OUT="models/apiary-${MODEL_TAG}-v1"
TRAIN_DATA="data/sft/v1.jsonl"
TEST_DATA="data/sft/v1.test.jsonl"

HEAD_NODE_IP=$(scontrol show hostnames "$SLURM_JOB_NODELIST" | head -n1)
HEAD_NODE_IP=$(getent hosts "$HEAD_NODE_IP" | awk '{print $1}')
export HEAD_NODE_IP

echo "================================================================"
echo "Apiary v3 training: $BASE_MODEL"
echo "Head node IP: $HEAD_NODE_IP"
echo "Nodes:        $SLURM_JOB_NUM_NODES"
echo "GPUs total:   $((SLURM_JOB_NUM_NODES * 8))"
echo "================================================================"

# ---------------------------------------------------------------------------
# Stage 1: abliteration (1 node, 8 H100s, ~30-90 min for 32B)
# ---------------------------------------------------------------------------

if [ ! -d "$ABLITERATED_DIR" ]; then
    echo "[stage 1/3] abliteration -> $ABLITERATED_DIR"
    srun --nodes=1 --ntasks=1 --gpus=8 --exclusive \
        python -m apiary_train.abliteration \
            --base-model "$BASE_MODEL" \
            --output "$ABLITERATED_DIR" \
            --harmful-prompts apiary_train/harmful_prompts.json \
            --harmless-prompts apiary_train/harmless_prompts.json \
            --dtype bfloat16 \
            --verbose
else
    echo "[stage 1/3] reusing existing abliterated weights at $ABLITERATED_DIR"
fi

# ---------------------------------------------------------------------------
# Stage 2: SFT LoRA (8 nodes x 8 H100 = 64 GPUs, ~4-8 hours for 32B + 60K examples)
# ---------------------------------------------------------------------------

echo "[stage 2/3] SFT LoRA -> $SFT_OUT"

srun --ntasks="$SLURM_JOB_NUM_NODES" --ntasks-per-node=1 \
    bash -c "accelerate launch \
        --config_file apiary_train/accelerate_multinode.yaml \
        --num_processes $((SLURM_JOB_NUM_NODES * 8)) \
        --num_machines $SLURM_JOB_NUM_NODES \
        --main_process_ip $HEAD_NODE_IP \
        --main_process_port 29500 \
        --machine_rank \$SLURM_NODEID \
        -m apiary_train.sft_lora \
            --base-model $BASE_MODEL \
            --abliterated-model $ABLITERATED_DIR \
            --train-data $TRAIN_DATA \
            --eval-data $TEST_DATA \
            --output $SFT_OUT \
            --batch-size 2 \
            --grad-accum 16 \
            --epochs 2 \
            --lr 1e-4 \
            --lora-r 64 \
            --lora-alpha 128 \
            --lora-target-modules q_proj,k_proj,v_proj,o_proj,gate_proj,up_proj,down_proj \
            --max-seq-len 8192 \
            --bf16 \
            --save-steps 250 \
            --eval-steps 250 \
            --logging-steps 10 \
            --report-to none \
            --seed 42"

# ---------------------------------------------------------------------------
# Stage 3: eval (1 node, 1 H100, ~30 min)
# ---------------------------------------------------------------------------

echo "[stage 3/3] eval -> $SFT_OUT/eval"

srun --nodes=1 --ntasks=1 --gpus=1 --exclusive \
    python -m apiary_train.eval \
        --model "$SFT_OUT" \
        --base-model "$BASE_MODEL" \
        --test-data "$TEST_DATA" \
        --output "$SFT_OUT/eval" \
        --max-new-tokens 512

echo "Done at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
