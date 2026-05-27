# Changelog

All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-05-28

The v1 to v2 pivot. v1 led with a CodeBERT classifier and framed the product
as probabilistic scoring. v2 leads with a self-hosted npm registry proxy
and frames the product as deterministic policy gating with an
insurance-grade evidence pipeline. The classifier is retained as one
supplementary signal.

### Added

- Self-hosted npm registry proxy (`apiary_proxy/`) speaking the npm registry
  API: metadata, scoped packages, tarball serving, `npm login` stub,
  `/-/ping`, `/healthz`, `/audit?limit=N`.
- 5-rule policy engine (`apiary_policy/`): release age, lifecycle script
  triage, `dist.integrity` SRI checksum verification (sha512 / sha384 /
  sha256), known-quarantine lookup, source-match stub. Composed in
  `decide_policy()` with explicit allow / quarantine / block semantics.
- Quarantine workflow (`apiary_quarantine/`) with `quarantine/policy.json`
  plus mandatory sibling rationale notes under `quarantine/notes/`. CLI
  subcommands: `add`, `promote`, `validate`. Designed as a git pre-commit
  hook so policy changes cannot land silently.
- LLM audit pipeline (`apiary_auditors/`) with three backends: OpenAI
  (`gpt-4o-mini`), Ollama (local `deepseek-coder:6.7b` or any abliterated
  variant), and Dwarfstar-style OpenAI-compatible endpoints. Prompt builder
  reserves 25% of context for the rubric and 75% for the package code.
- Pre-audit cache seeder (`apiary_cache/`) that runs the policy and LLM
  audit against the top-N popular packages so install-time decisions hit
  the cache.
- `demo/run_incident_replay.py`: retroactive incident replay driver. Three
  faithful reconstructions ship in-tree (`postmark-mcp-1.0.16`,
  `postmark-mcp-1.0.12`, `lodash-4.17.21`), each producing a colored rule
  table, a verdict banner, and a rendered Control Evidence Memo.
- Control Evidence Memo template (`apiary_quarantine/templates/`) written
  in SOC 2 / ISO 27001 A.8.28 / NIST SSDF PS.3.1 vocabulary, mapped to
  CIS Control 16. Renders to Markdown, exportable to PDF.
- Insurance economics one-pager (`pitch/underwriter-economics.md`) with
  cited underwriting math anchored to NAIC 2024, Munich Re, Coalition,
  Verizon DBIR 2024, and Sonatype 2024 reports.
- Two-slide insurance economics insert for the pitch deck
  (`pitch/insurance-economics-slides.md`).
- WhatsApp brief for Andreas (`pitch/whatsapp-to-andreas.md`) consolidating
  the v2 status and decision points before the pitch.

### Changed

- CodeBERT classifier demoted from product centerpiece to supplementary
  signal feeding the LLM audit pipeline. v1 classifier code retained in
  `scripts/`, `modulewarden_gate/`, and `bumblebee_bridge/`.
- README rewritten to lead with the v2 registry-proxy architecture and the
  60-second elevator pitch. Added a "What's NOT included" section
  enumerating the source-match stub, the figshare label fix, and the LRU
  eviction gap.
- Slide deck rewritten as 12 slides matching the v2 architecture. The
  insurance economics slides land between the live demo and the roadmap,
  putting the actuarial frame in the judges' heads before the ask.
- Landing page updated with insurance-grade vocabulary and a link to the
  Control Evidence Memo template.
- Attack catalogue cleaned: removed worm-propagation patterns ("worms not
  applicable" per design, since the gate sits ahead of the install).
- `pyproject.toml`: swapped `xgboost` for `lightgbm`, added `httpx` and
  `rich` for the proxy and demo replay output.

### Fixed (Security)

- SSRF in `modulewarden_gate` `/score` endpoint. The endpoint now enforces
  a hostname allowlist before any upstream fetch.
- Path traversal in `scripts/score_package.py`. Tarball extraction now goes
  through a safe extractor that rejects entries with absolute paths,
  parent traversal, or symlinks pointing outside the extract root.
- Slurm script CLI args mismatched `train_codebert.py`. Fixed argument
  parsing so the Leonardo job no longer fails at launch.

## [1.0.0] - 2026-05-27

Hackathon scaffold day. The full v1 product as it stood the morning before
the v2 pivot.

### Added

- Initial scaffold: CodeBERT + LoRA fine-tune pipeline on the figshare NPM
  Malicious Package Study benchmark (210K labelled releases, CC BY 4.0).
- Synthetic data generator with a 22-pattern attack catalogue drawn from
  OSSF taxonomies, CWE entries for supply chain attacks, and the academic
  literature on npm-specific patterns.
- FastAPI gate (`modulewarden_gate/`) with allow / quarantine / block
  thresholds driven by a hot-reloadable `thresholds.yaml`.
- Bumblebee NDJSON bridge (`bumblebee_bridge/`) consuming Perplexity's
  open-source inventory feed and forwarding each record to the scoring
  endpoint.
- Slurm training pipeline (`slurm/train.slurm`) targeting a single A100 on
  Leonardo. LoRA at r=16, alpha=32.
- Bench gate (`scripts/score_package.py`) for offline scoring of a single
  package archive.
- LICENSE (Apache 2.0) and project scaffolding (`pyproject.toml`,
  `.gitignore`).
