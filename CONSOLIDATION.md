# Consolidation: apiary and ModuleWarden

This document maps the relationship between two repos that arrived at
the same problem from different starting points: apiary (this repo,
the Zero-One Hack submission runtime) and ModuleWarden
(apetersson/ModuleWarden, the production architecture).

## TL;DR

Andreas authored ModuleWarden as a backlog-first architecture spec for
a self-hosted npm ingress gate against compromised-maintainer attacks.
Andrew built apiary in parallel as a working hackathon submission with
a live registry proxy, policy engine, three replayed incidents, an
H100 training stack, and an insurance-grade audit memo. Two repos
exist because the work happened on two clocks: ModuleWarden is the
production architecture we port into post-hackathon, apiary is the
runtime that ships Sunday. This document maps the consolidation.

## What apiary IS

The Zero-One Hack submission. Working from the first commit through
demo day:

- Registry proxy with metadata rewrite and tarball serving
  (`apiary_proxy/`)
- Five-rule deterministic policy engine
  (`apiary_policy/rules.py`)
- Real upstream-repo source-match diff with SHA256 file comparison
  and stem fallback for compiled output
  (`apiary_policy/source_match.py`, 520 LOC, live tested at 99% match
  against lodash@4.17.21 in 16.8s)
- LRU tarball cache eviction with configurable disk quota
  (`apiary_proxy/cache_lru.py`)
- Per-environment policy presets (dev / preprod / prod) with YAML
  overrides (`apiary_policy/environments.py`)
- Quarantine workflow with mandatory sibling rationale notes and
  pre-commit validate (`apiary_quarantine/`)
- LLM audit pipeline with three pluggable backends (dwarfstar /
  ollama / openai-compatible) (`apiary_auditors/`)
- Insurance-grade Control Evidence Memo rendered via Jinja2 (and a
  plain-text fallback that never fails to render)
- Three retroactive incident replays (postmark-mcp 1.0.12 clean,
  postmark-mcp 1.0.16 malicious, lodash 4.17.21 baseline) with golden
  smoke tests
- H100 training stack: abliterated + SFT LoRA on GLM 5.1 32B / DeepSeek
  4 Pro, figshare NPM Malicious Package Study + 50K synthetic examples
  (`apiary_train/`, Leonardo or equivalent 64x H100 cluster)
- Pitch materials, video script, underwriter economics, Q&A prep

## What ModuleWarden IS

The production architecture spec. Backlog-first, with a sharp threat
model and a careful contract for how each component composes:

- Formal threat-model contract: Class A (compromised maintainer
  version bump, primary focus), Class B (supply-chain malware, not
  optimized for), Class C (novel vulnerability discovery, pattern
  checks only)
- Durable Postgres persistence with Prisma schema (decision history,
  evidence references, override audit trail)
- Per-job Docker audit isolation with pg-boss job queue and retry
  policy
- Verdaccio backing with promote-only semantics (no install can land
  unless an allow decision exists)
- Prompt secrecy model: audit prompts are server-side artifacts; the
  client never sees them
- Override and re-audit campaign semantics: admin verdict overrides
  are recorded with admin identity, scope, reason, and supersedes
  pointer; re-audit campaigns can be triggered on prompt-version or
  model-profile changes

## Concepts apiary BORROWS from ModuleWarden

These ship in apiary v2.0 as adopted vocabulary:

- **Threat Class taxonomy** (A / B / C) - now stamped on the Control
  Evidence Memo and printed in the demo header
- **Verdict** primitive (`allow` / `block` / `quarantine`) - matches
  ModuleWarden exactly
- **Decision** envelope (with `reasonSummary`, `promptVersions`,
  `modelProfile`, `scores`, `evidenceReferences`, `piSessionId`,
  `piRunId`, `actorType`, `predecessorVersion`, `predecessorHash`) -
  mirrored in `shared/types.py` as Python dataclasses
- **AuditContext** (package identity + predecessor + trigger) -
  mirrored
- **PackageIdentity** (name, version, registry, tarball hash) -
  mirrored
- **Override** primitive (admin identity, scope, reason, timestamp,
  supersedes) - placeholder in `shared/types.py`; not yet wired into
  apiary, but the vocabulary is available
- **Prompt-secrecy intent** - apiary stores audit prompts server-side
  under `apiary_auditors/prompts/`; the LLM backend handles them and
  the client only sees the verdict envelope

## What apiary explicitly punts on (acknowledged)

We name these so judges and Andreas both know where the seams are:

- **Durable Postgres persistence**. Apiary writes audit decisions to
  JSONL under `data/` with TTL eviction. ModuleWarden's Prisma schema
  is the right shape for production. Migration is a port-the-schema
  exercise, not a redesign.
- **Per-job Docker audit isolation**. Apiary runs audit work inline
  through asyncio. ModuleWarden runs each audit in a per-job Docker
  container with pg-boss orchestration and retry policy. Apiary's
  inline path was the right call for hackathon turnaround.
- **Verdaccio promote-only backing**. Apiary proxies the upstream
  registry directly and serves cached tarballs. ModuleWarden gates
  with Verdaccio so no install can resolve unless a promote happened.
  This is the cleaner production posture.
- **Formal Override and Re-audit campaigns**. Apiary has
  `quarantine` -> `allowlist` promotion (with mandatory rationale
  notes) but does not implement admin-identity-stamped overrides or
  campaign re-audits triggered by prompt-version or model-profile
  changes. The vocabulary is in `shared/types.py` so the migration
  is mechanical.
- **`POST /-/v1/login` production auth**. Apiary accepts any
  credentials. Production deployment proxies the upstream registry's
  auth flow; we have not implemented that.
- **Multi-tenant proxy**. One apiary instance serves one org unit.
  Multi-tenant deployments need per-tenant cache partitioning, policy
  overlays, and audit log isolation. Queued for SOC 2 prep in Q4.

## Post-hackathon consolidation plan

Concrete steps to converge the two repos onto ModuleWarden's stack:

1. **Port the policy rules from Python to TypeScript** under
   ModuleWarden's worker package. The five-rule engine and the
   source-match diff translate one-for-one. Apiary stays as the
   reference implementation and the training stack home.
2. **Adopt ModuleWarden's Prisma schema** for decision persistence.
   Migrate the JSONL audit log into Postgres. The `Decision`
   dataclass in `shared/types.py` already matches the schema column-
   for-column.
3. **Adopt pg-boss for jobs** in ModuleWarden's worker package. The
   apiary asyncio inline path is correct for hackathon scale but
   does not survive a real concurrent install storm.
4. **Move audit runners into per-job Docker** as ModuleWarden
   prescribes. Apiary's `apiary_auditors/llm_audit.py` becomes the
   in-container runner; orchestration moves to pg-boss.
5. **Fold `apiary_train/` H100 pipeline into ModuleWarden's worker
   package**. The abliteration + SFT LoRA pipeline is the part that
   does not exist in ModuleWarden's spec; it becomes the model-
   training subsystem.
6. **Replace apiary's direct upstream proxy with Verdaccio**. The
   proxy stays as a reference for the cache+rewrite path; production
   routes through Verdaccio with promote-only gates.

## Credits and attribution

The threat model (Class A / B / C taxonomy), the verdict vocabulary
(`allow` / `block` / `quarantine`), the Decision envelope shape, the
AuditContext primitive, and the production architecture (Verdaccio +
Postgres + pg-boss + per-job Docker isolation + prompt secrecy) all
come from Andreas's ModuleWarden v1 architecture document.

Apiary v2.0 is the runtime that ships Sunday. ModuleWarden is the
architecture we port into post-hackathon. Both repos contribute.
This is consolidation prep, not competition.
