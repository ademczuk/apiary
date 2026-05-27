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
`modulewarden_gate/`, and `bumblebee_bridge/`, and remains useful as one
supplementary signal feeding the audit pipeline. It is no longer the
centerpiece. A score is not a control. A rule is.

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

## What's NOT included

The v2.0 ship line is honest about what we punted. Judges who poke at the
repo will find these. We'd rather you find them in the README than in the
code.

- **Source-match rule** (`apiary_policy/rules.py`). The `source_match` rule
  is a stub that always returns False. The demo replay short-circuits this
  for the three baselines with an explicit allowlist. Closing it out
  requires attesting publisher-to-repo provenance against a known set of
  signed commits or release artifacts; that work is queued for Q3 2026.
- **Figshare label fix**. The v1 classifier's training corpus has one
  mislabeled benign batch from the figshare NPM Malicious Package Study
  that we identified during model evaluation. The fix is documented but
  not yet applied; rerunning the LoRA fine-tune is a Leonardo job we did
  not schedule before the ship date.
- **LRU cache eviction**. The proxy cache uses simple TTL eviction (1h
  metadata, persistent tarballs). LRU eviction with a configurable disk
  quota is the right shape for production; for the hackathon we leaned
  on "disks are big" and shipped TTL.
- **Multi-tenant proxy**. One Apiary instance serves one organizational
  unit today. Multi-tenant deployments need per-tenant cache partitioning,
  policy overlays, and audit log isolation. Conceptually simple, queued
  for the SOC 2 prep work in Q4.
- **Production-grade auth on `POST /-/v1/login`**. The stub accepts any
  credentials. A production deployment proxies the upstream registry's
  auth flow; we have not implemented that.

## v1 classifier (still present)

The CodeBERT LoRA fine-tune and LightGBM fallback are still in the tree
because they remain useful as a probabilistic signal feeding the audit
pipeline. The training pipeline targets the figshare NPM Malicious
Package Study (210K labelled releases, CC BY 4.0). See
`scripts/train_codebert.py` and `slurm/train.slurm`.

## Layout

- `apiary_proxy/` FastAPI registry proxy with cache + policy gating
- `apiary_policy/` policy engine and SRI checksum verification
- `apiary_quarantine/` policy file + rationale workflow with CLI
- `apiary_auditors/` LLM audit prompt builder + OpenAI / Ollama / Dwarfstar backends
- `apiary_cache/` cache seeder that pre-audits the top-N popular packages
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
