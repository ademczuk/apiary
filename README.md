# Apiary

Apiary is a self-hosted npm registry proxy that gates package installs against
deterministic security policy before the tarball ships to your developer.
Think Verdaccio plus Snyk's intentions plus a SOC 2 evidence pipeline, in one
binary.

Built for the Apiary Zero-One Hack and aimed at insurance underwriters and
brokers (UNIQA, Munich Re) who care about premium-grade signal on the
third-party code that gets pulled into the office tomorrow morning.

## Why this shape

Carriers cannot underwrite "we ran a classifier over public npm". They can
underwrite "every install in the policyholder's CI went through a gate that
held the tarball, recorded the decision, and produced an audit trail". The
gate has to be operationally boring: fast, on-prem, no SaaS round trip, no
agent on developer laptops.

Apiary's v2 architecture is that gate. Four pieces:

1. **Registry proxy** (`apiary_proxy/`). FastAPI server that speaks the npm
   registry API (metadata, tarballs, `npm login` stub, `/-/ping`). Cache
   directory on disk, configurable upstream, every request logged.
2. **Policy engine** (`apiary_policy/`). Five rules with explicit allow /
   quarantine / block semantics: release age, lifecycle script triage,
   `dist.integrity` checksum verification (sha512 / sha384 / sha256),
   known-quarantine lookup, source-match stub. Composed in
   `decide_policy()`; the proxy calls it on every tarball serve.
3. **Quarantine workflow** (`apiary_quarantine/`). `quarantine/policy.json`
   plus mandatory sibling rationale notes under `quarantine/notes/`. The
   `validate` subcommand is a git pre-commit hook so policy changes can
   never land silently.
4. **LLM-driven audit** (`apiary_auditors/`). Reserves 25% of the model
   context for the audit rubric and 75% for the package code. Three
   backends ship in-tree: OpenAI (`gpt-4o-mini`), Ollama (local
   `deepseek-coder:6.7b` or any abliterated variant), and Dwarfstar-style
   OpenAI-compatible endpoints. The cache seeder (`apiary_cache.seed`)
   pre-audits a few thousand top packages so the common case is a cache
   hit at install time.

The CodeBERT classifier from v1 is still in the tree under `scripts/`,
`modulewarden_gate/`, and `bumblebee_bridge/`. It is labeled as legacy
supplementary signal in v3, not the primary training target. A score
is not a control. A rule is.

For the v3 audit model we abliterate + LoRA fine-tune a 32B-70B class
model (GLM 5.1 32B or DeepSeek 4 Pro). See "Training the audit model"
below.

## Quickstart

Five commands from clone to a working gate.

```bash
git clone https://github.com/ademczuk/apiary
cd apiary
uv venv && source .venv/bin/activate
uv pip install -e .
python -m apiary_proxy.proxy --port 4873 --cache-dir data/proxy-cache
# then in another terminal:
npm config set registry http://localhost:4873/
npm install lodash
```

Watch the gate log. Every install fires the policy engine. Allowed installs
return 200, quarantined installs return 202 with a `Retry-After` header,
blocked installs return 451.

To replay the September 2025 postmark-mcp incident against the same policy
engine and render an insurance-grade Control Evidence Memo:

```bash
python -m demo.run_incident_replay --incident postmark-mcp-1.0.16
```

Three incident reconstructions ship in-tree: `postmark-mcp-1.0.16` (the
malicious release), `postmark-mcp-1.0.12` (the legitimate prior version),
and `lodash-4.17.21` (a clean popular-package baseline). The memo lands in
`demo/outputs/`.

## Endpoint summary

| Path | Behaviour |
|------|-----------|
| `GET /{package}` | Fetches metadata from upstream, rewrites `dist.tarball` URLs to point back at the proxy. Cache TTL 1h. |
| `GET /@{scope}/{name}` | Same as above for scoped packages. |
| `GET /{package}/-/{file}.tgz` | Cache lookup, falls back to upstream, runs the policy, returns 200 (allow) / 451 (block) / 202 (quarantine). |
| `GET /@{scope}/{name}/-/{file}.tgz` | Same for scoped packages. |
| `POST /-/v1/login` | Accept-anything stub so `npm login` does not error. |
| `GET /-/ping` | npm liveness probe. |
| `GET /healthz` | Operator health (upstream URL, cache dir, quarantine status). |
| `GET /audit?limit=50` | Tail of the structured audit log. |

## Quarantine workflow

Every policy change requires a sibling rationale Markdown file:

```bash
python -m apiary_quarantine.workflow add lodash@4.17.21 \
    --rationale "Pre-approved baseline, manually audited 2026-05-27, see ABC123."

python -m apiary_quarantine.workflow promote lodash@4.17.21

python -m apiary_quarantine.workflow validate
```

`validate` returns nonzero if any policy entry lacks a note or any note is
orphaned. Wire it into a git pre-commit hook to keep the audit trail
honest.

## What ships in v2.0 (corrections to earlier drafts)

Two items that earlier drafts of this README listed as "deferred" or
"stub" ship for real in the v2.0 line. Calling them out so the doc
matches the code:

- **source_match** is a real upstream-repo diff
  (`apiary_policy/source_match.py`, 520 LOC). It downloads the upstream
  git archive at `gitHead`, extracts both trees, and compares files
  by SHA256 with stem fallback for compiled output. Tri-state return
  (pass / fail / skip) so a missing pointer routes to quarantine, not
  block. Cached under `data/source-cache/`. Live test against
  `lodash@4.17.21` yields 99% file match (1048 / 1049 files) in 16.8s.
  The legacy stub described in earlier drafts was replaced in commit
  `9fb21f1`.
- **LRU cache eviction** ships at `apiary_proxy/cache_lru.py`. Background
  asyncio sweep over `data/proxy-cache`, mtime-based recency, tarballs
  evicted oldest-first when the on-disk total exceeds `max_bytes`
  (default 10 GiB) down to 80% of max. Sidecar `.cache-stats.json` for
  ops visibility. Earlier drafts saying "TTL only" are out of date.

## What's NOT included

The v2.0 ship line is honest about what we punted. Judges who poke at the
repo will find these. We'd rather you find them in the README than in the
code.

- **Figshare label fix**. The v1 classifier's training corpus has one
  mislabeled benign batch from the figshare NPM Malicious Package Study
  that we identified during model evaluation. The fix is documented but
  not yet applied; rerunning the LoRA fine-tune is a Leonardo job we did
  not schedule before the ship date.
- **Multi-tenant proxy**. One Apiary instance serves one organizational
  unit today. Multi-tenant deployments need per-tenant cache partitioning,
  policy overlays, and audit log isolation. Conceptually simple, queued
  for the SOC 2 prep work in Q4.
- **Production-grade auth on `POST /-/v1/login`**. The stub accepts any
  credentials. A production deployment proxies the upstream registry's
  auth flow; we have not implemented that.

## Training the audit model

Apiary's LLM audit backend can be swapped out per deployment. For the
v3 reference model we abliterate and SFT fine-tune GLM 5.1 32B (or
DeepSeek 4 Pro) on the figshare NPM Malicious Package Study plus 50K
synthetic examples generated from our 22-pattern attack catalog.

Abliteration removes refusal cascades on security-analysis prompts via
the Failspy refusal-direction orthogonalization technique
(arXiv:2406.11717). The SFT fine-tune teaches the model to produce
structured JSON verdicts on npm packages.

Training pipeline (Leonardo or equivalent 64x H100 cluster):

```bash
# 1. Convert corpus to instruction format
python -m apiary_train.data_prep \
    --figshare-archive data/raw/figshare/63179326_NPMStudy.zip \
    --synthetic-dir data/synthetic/v1 \
    --output data/sft/v1.jsonl \
    --max-len 8192 --shuffle --seed 42

# 2. Distributed train (8 nodes x 8 H100)
BASE_MODEL=THUDM/glm-5.1-32b-base sbatch slurm/abliterate_then_sft.slurm

# 3. Held-out eval
python -m apiary_train.eval \
    --model models/apiary-glm-5.1-32b-base-v1 \
    --base-model THUDM/glm-5.1-32b-base \
    --test-data data/sft/v1.test.jsonl
```

Rehearsal pipeline (cheap, validates correctness on a 1.5B model in
about thirty minutes on a single GPU):

```bash
python -m apiary_train.rehearsal \
    --base-model Qwen/Qwen2.5-Coder-1.5B --quick
```

Production handoff: the trained LoRA adapter is loaded by
`apiary_auditors.llm_audit.ApiaryFineTunedBackend` (factory name
`apiary-finetuned`). The proxy switches to it via the audit-backend
config alongside the existing `openai` / `ollama` / `dwarfstar`
backends.

## v1 classifier (legacy / supplementary)

The CodeBERT LoRA fine-tune and LightGBM fallback are still in the tree
as a supplementary probabilistic signal that can feed the audit
pipeline. They are no longer the primary training target. See
`scripts/train_codebert.py` and `slurm/train.slurm`.

## Layout

- `apiary_proxy/` FastAPI registry proxy with cache + policy gating
- `apiary_policy/` policy engine and SRI checksum verification
- `apiary_quarantine/` policy file + rationale workflow with CLI
- `apiary_auditors/` LLM audit prompt builder + OpenAI / Ollama / Dwarfstar backends
- `apiary_cache/` cache seeder that pre-audits the top-N popular packages
- `apiary_train/` v3 abliteration + LoRA SFT pipeline (primary training story)
- `demo/` incident replay driver, three faithful reconstructions, expected outputs
- `pitch/` slide deck, Q&A prep, insurance economics one-pager, video script
- `scripts/` v1 data and classifier pipeline (still functional, feeds audit)
- `modulewarden_gate/` v1 FastAPI scoring endpoint (still functional)
- `bumblebee_bridge/` v1 stdin NDJSON consumer for Bumblebee inventory scans
- `data/patterns/` attack catalogue used for synthetic training data

## Data sources

Primary: figshare NPM Malicious Package Study (210K records, CC BY 4.0).
Backup: OSSF malicious-packages OSV feed (213K npm OSV records, Apache 2.0).
See `data/README.md`.

## License

Apache 2.0. See `LICENSE`.
