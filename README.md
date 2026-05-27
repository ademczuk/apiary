# Apiary: a self-hosted npm registry gate for the insurance supply chain

Apiary is an npm registry proxy plus policy gate plus quarantine workflow. It
sits between a developer (or a CI pipeline) and the public npm registry,
caches every tarball it serves, and applies a configurable allow / quarantine
/ block decision before any byte reaches a developer machine. Built for the
Apiary Zero-One Hack and aimed at insurance underwriters and brokers (UNIQA,
Munich Re) who care about premium-grade signal on third-party code that gets
pulled into the office tomorrow morning.

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
   OpenAI-compatible endpoints. The cache seeder
   (`apiary_cache.seed`) pre-audits a few thousand top packages so the
   common case is a cache hit at install time.

The CodeBERT classifier from v1 is still in the tree under `scripts/`,
`modulewarden_gate/`, and `bumblebee_bridge/`, and remains usable as one
signal among several. It is no longer the centerpiece.

## Quick start

```bash
# Python 3.11, uv recommended
uv venv
uv pip install -e .

# Initialise the quarantine policy
python -m apiary_quarantine.workflow validate

# Seed the proxy cache with the top 2000 packages (heuristics + policy only)
python -m apiary_cache.seed --count 2000 --workers 8

# Or seed with full LLM audit via local Ollama
python -m apiary_cache.seed --count 200 --workers 2 \
    --audit-backend ollama --audit-model deepseek-coder:6.7b

# Run the proxy on port 4873
python -m apiary_proxy.proxy --port 4873 \
    --cache-dir data/proxy-cache \
    --upstream https://registry.npmjs.org

# Point npm at it
npm config set registry http://127.0.0.1:4873
npm install lodash
```

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

## v1 classifier (still present)

The CodeBERT LoRA fine-tune and LightGBM fallback are still in the tree
because they remain useful as a probabilistic signal for packages we have
not yet audited. The training pipeline targets the figshare NPM Malicious
Package Study (210K labelled releases, CC BY 4.0). See
`scripts/train_codebert.py` and `slurm/train.slurm`.

## Layout

- `apiary_proxy/` FastAPI registry proxy with cache + policy gating
- `apiary_policy/` policy engine and SRI checksum verification
- `apiary_quarantine/` policy file + rationale workflow with CLI
- `apiary_auditors/` LLM audit prompt builder + OpenAI / Ollama / Dwarfstar backends
- `apiary_cache/` cache seeder that pre-audits the top-N popular packages
- `scripts/` v1 data and classifier pipeline (still functional)
- `modulewarden_gate/` v1 FastAPI scoring endpoint (still functional)
- `bumblebee_bridge/` v1 stdin NDJSON consumer for Bumblebee inventory scans
- `data/patterns/` attack catalogue used for synthetic training data

## Data sources

Primary: figshare NPM Malicious Package Study (210K records, CC BY 4.0).
Backup: OSSF malicious-packages OSV feed (213K npm OSV records, Apache 2.0).
See `data/README.md`.

## License

Apache 2.0. See `LICENSE`.
