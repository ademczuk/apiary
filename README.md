# Apiary: ModuleWarden Gate for NPM Supply Chain

A 36-hour hackathon project. Train a malicious-npm-package classifier and ship it as a developer-facing install gate that turns Bumblebee inventory scans into allow / quarantine / block decisions.

## 60-second pitch

Developers install npm packages every day. A handful of those packages are malicious: typosquats, install-script droppers, exfiltration payloads. Bumblebee (Perplexity's open-source agent) already inventories what is installed. ModuleWarden adds the verdict: each package gets a score, an evidence list, and a routed action. The gate fits between Bumblebee and the developer's terminal, the CI pipeline, or the editor.

The model is a LoRA fine-tune of CodeBERT over the figshare NPM Malicious Package Study (210K labelled npm releases, CC BY 4.0). A gradient-booster on hand-extracted features (AST shape, install-script presence, string entropy) serves as the always-available fallback. Conformal calibration via MAPIE gives the gate honest confidence intervals at decision time.

## Run

```bash
# Python 3.11, uv recommended
uv venv
uv pip install -e .

# Download the dataset (figshare DOI 10.6084/m9.figshare.31869370)
python scripts/download_figshare.py

# Preprocess into a HuggingFace Dataset
python scripts/preprocess.py

# Train the fallback gradient-booster first (less than 60s on CPU)
python scripts/train_xgb_fallback.py

# Train the CodeBERT LoRA head (Leonardo slurm, see slurm/train.slurm)
python scripts/train_codebert.py

# Evaluate
python scripts/eval.py

# Score one package
python scripts/score_package.py --package event-stream --version 3.3.6

# Start the gate
uvicorn modulewarden_gate.gate:app --port 8000

# Pipe Bumblebee output through the gate
bumblebee scan --profile project --root ~/code | python -m bumblebee_bridge.ingest
```

## Demo

Run `demo/live_demo.sh` for the 60-second judges' walkthrough. It pipes 10 known-malicious npm package records from OSSF through the gate and renders the decision table.

## Layout

- `scripts/` data and model pipeline
- `modulewarden_gate/` FastAPI scoring endpoint with configurable thresholds
- `bumblebee_bridge/` stdin NDJSON consumer that talks to the gate
- `demo/` live demo script and seed packages
- `slurm/` Leonardo training submission

## Data sources

Primary: figshare NPM Malicious Package Study (210K records, CC BY 4.0). See `data/README.md`.

Backup: OSSF malicious-packages OSV feed (213,418 npm OSV records, Apache 2.0). See `data/README.md`.

Excluded: Backstabbers Knife Collection. Access requires emailing the maintainers from an institutional account, which is outside the hackathon time budget.
