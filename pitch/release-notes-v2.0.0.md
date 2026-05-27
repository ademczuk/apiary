# Apiary v2.0.0

Apiary is a self-hosted npm registry proxy that gates package installs against
deterministic security policy before the tarball ships to a developer. v2.0.0
is the first ship line of the architecture insurance underwriters can price
against: deterministic rules, on-prem deployment, Control Evidence Memo on
every decision.

Live landing page: https://ademczuk.github.io/modulewarden-website/

## Highlights

- npm registry proxy that speaks the full registry API, caches every tarball
  it serves, and applies allow / quarantine / block policy before any byte
  reaches a developer machine.
- Five deterministic policy rules: release age, lifecycle script triage,
  `dist.integrity` SRI checksum verification, known-quarantine lookup,
  source-match (stub in this release).
- Quarantine workflow with sibling rationale Markdown files validated by a
  git pre-commit hook. Policy changes cannot land silently.
- LLM audit pipeline with three backends (OpenAI, local Ollama, Dwarfstar)
  and a cache seeder that pre-audits popular packages overnight.
- Retroactive incident replay driver that runs the deterministic gate
  against faithful reconstructions of real-world npm supply-chain incidents
  and renders an insurance-grade Control Evidence Memo from the result.

## Architecture

Four pieces, all self-hosted, no SaaS round trip.

- `apiary_proxy/` is the FastAPI registry proxy. Speaks npm registry API,
  caches metadata for 1h, persists tarballs to disk, rewrites
  `dist.tarball` URLs to route every install through the gate.
- `apiary_policy/` is the 5-rule policy engine. Each rule returns
  `(passed, reason)`. `decide_policy()` composes them into a single
  verdict with an evidence list. The proxy calls it on every tarball serve.
- `apiary_quarantine/` is the workflow tooling for `quarantine/policy.json`
  plus mandatory rationale notes. CLI subcommands `add`, `promote`,
  `validate`. Drop the `validate` call into your git pre-commit and the
  audit trail stays honest.
- `apiary_auditors/` is the LLM audit pipeline. Reserves 25 percent of
  model context for the audit rubric and 75 percent for the package code.
  Three backends ship in-tree.

The v1 CodeBERT classifier from the figshare benchmark training is still in
the tree under `scripts/`, `modulewarden_gate/`, and `bumblebee_bridge/`. It
now feeds the LLM audit pipeline as one supplementary signal rather than
driving the gate decision.

## Live demo

```bash
python -m demo.run_incident_replay --incident postmark-mcp-1.0.16
```

Faithful reconstruction of the September 2025 postmark-mcp incident. The
deterministic policy fires, the gate produces a BLOCK verdict, and a Control
Evidence Memo lands in `demo/outputs/`. The replay is fully offline; no LLM
backend required.

Two clean baselines also ship: `--incident postmark-mcp-1.0.12` (the last
known-clean release) and `--incident lodash-4.17.21` (popular package
baseline). Both produce ALLOW verdicts with their own memos.

## Insurance positioning

Apiary's underwriting story sits in `pitch/underwriter-economics.md`. The
short version: for an illustrative Austrian SME with a 142k EUR cyber premium
and a 41 percent expected loss ratio, deploying Apiary plus the Control
Evidence Memo pipeline supports a 12.5 percent control-class credit (anchored
to Coalition's published MDR figure) and a loss ratio improvement to the 27
to 30 percent band. Per-account margin uplift of 11 to 14 percentage points
on the eligible segment; 2 to 4 points across the full book once eligibility
is weighted. All numbers anchored to public industry reports (NAIC 2024,
Munich Re, Coalition, Verizon DBIR 2024, Sonatype 2024).

## Known limitations

- `source_match` rule is a stub returning False. The demo replay
  short-circuits this for the three baselines with an explicit allowlist.
- v1 classifier training data has one mislabeled benign batch from the
  figshare corpus. Fix documented, rerun not yet scheduled.
- Proxy cache uses TTL eviction only. LRU with disk quota is the right
  shape for production and is queued for Q3.
- Single-tenant only. Multi-tenant deployments need per-tenant cache
  partitioning, policy overlays, and audit log isolation.
- `POST /-/v1/login` is an accept-anything stub. Production deployments
  proxy the upstream registry's auth flow.

## Roadmap

- Q3 2026: close the `source_match` rule, PyPI proxy with the same
  architecture, federated audit prototype.
- Q4 2026: RubyGems proxy, multi-tenant cache partitioning, SOC 2 Type II
  prep work.
- 2027: SOC 2 Type II certification, registry mirror integration that
  refuses to serve blocked tarballs to the local cache.

## Pitch materials

- `pitch/slide-deck.md` - 12-slide deck for the pitch
- `pitch/q-and-a-prep.md` - 25 anticipated questions with prepared answers
- `pitch/underwriter-economics.md` - the actuarial math, fully cited
- `pitch/insurance-economics-slides.md` - two-slide pitch insert
- `pitch/demo-runbook.md` - the demo, step by step

## License

Apache 2.0.
