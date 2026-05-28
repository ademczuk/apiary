# ENHANCE_MODULEWARDEN.md - port-from-apiary plan

> Companion to `docs/SUBMIT_APIARY.md`. If we consolidate INTO ModuleWarden instead of submitting apiary, here are the concrete TypeScript port plans.

## TL;DR

Total port work: **~70-90 engineer-hours** for the demo-critical pieces; **~150-200h** to port everything. We have ~30 hours of team capacity. **Math does not close on pre-Sunday consolidation.** Recommendation: post-hackathon merge, with the 3 highest-impact ports prioritized for the first sprint.

## Highest-impact ports

### 1. Source-match (apiary_policy/source_match.py:1-520)

**What apiary has**: real upstream-repo file diff with SHA256, 95% threshold. Lodash live test 99% match in 16.8s.

**What MW has**: "tarball diverges materially from source" listed in threat model `docs/architecture.md` but no implementation.

**Port destination**: `packages/api-proxy/src/services/source-match.ts`

**TS skeleton**:
```typescript
import { createHash } from 'crypto';
import { Octokit } from '@octokit/rest';
import type { PackageMetadata } from '@apiary/shared';

export interface SourceMatchResult {
  passed: boolean;
  matchRatio: number;
  upstreamSha: string;
  suspiciousFiles: string[];
}

export async function checkSourceMatch(
  metadata: PackageMetadata,
  tarballBuffer: Buffer,
): Promise<SourceMatchResult | "skipped"> {
  if (!metadata.repositoryUrl) return "skipped";

  const { owner, repo } = parseGithubUrl(metadata.repositoryUrl);
  const upstreamArchive = await fetchUpstreamArchive(owner, repo, metadata.gitHead);
  const tarballFiles = extractTarballSafe(tarballBuffer);
  const upstreamFiles = extractArchive(upstreamArchive);

  return diffFileTrees(tarballFiles, upstreamFiles, { threshold: 0.95 });
}
```

**Dependencies**: `@octokit/rest` (or `simple-git`), `tar-stream`, `crypto` (stdlib).

**Estimated hours**: 12-16h (matching heuristics subtle; TS+Webpack packages have noisier diffs than lodash's clean 99%).

### 2. Per-environment policy tiers (apiary_policy/environments.py:1-229)

**What apiary has**: dev/preprod/prod tiers with explicit thresholds + YAML override loader.

**What MW has**: doesn't tier env policy in shipped code.

**Port destination**: `packages/api-proxy/src/services/environments.ts` + extend `packages/shared/src/config.ts`.

**TS skeleton**:
```typescript
export type EnvironmentName = 'dev' | 'preprod' | 'prod';

export interface EnvironmentPolicy {
  name: EnvironmentName;
  minReleaseAgeDays: number;
  installScripts: 'allow' | 'warn' | 'deny';
  requireSourceMatch: boolean;
  requireChecksum: boolean;
  failOpenOnAuditError: boolean;
  blockThreshold: number;
  logOnly: boolean;
}

export const DEFAULT_ENVIRONMENTS: Record<EnvironmentName, EnvironmentPolicy> = {
  dev:     { name: 'dev',     minReleaseAgeDays: 0,  installScripts: 'warn', requireSourceMatch: false, requireChecksum: false, failOpenOnAuditError: true,  blockThreshold: 0.5, logOnly: true  },
  preprod: { name: 'preprod', minReleaseAgeDays: 7,  installScripts: 'deny', requireSourceMatch: true,  requireChecksum: true,  failOpenOnAuditError: false, blockThreshold: 0.3, logOnly: false },
  prod:    { name: 'prod',    minReleaseAgeDays: 14, installScripts: 'deny', requireSourceMatch: true,  requireChecksum: true,  failOpenOnAuditError: false, blockThreshold: 0.2, logOnly: false },
};

export async function loadEnvironmentPolicy(envName: EnvironmentName, configPath?: string): Promise<EnvironmentPolicy> { ... }
```

**Dependencies**: existing yaml loader; no new deps.

**Estimated hours**: 4-6h.

### 3. Attack pattern catalog + injection generator (data/patterns/attack-catalog.yaml + apiary_train/data_prep.py + injector)

**What apiary has**: 26-pattern catalog (1,500+ lines YAML), real-world incident citations, injection templates, seed-reproducible 8x synthetic generator.

**What MW has**: threat categories named, no catalog, no generator.

**Port plan**: keep catalog as YAML — copy `data/patterns/attack-catalog.yaml` directly. Generator stays in Python (heavy reliance on transformers ecosystem). MW shells out via subprocess.

**Port destination**:
- `packages/shared/data/attack-catalog.yaml` (just a copy)
- `packages/worker/src/services/synthetic-data-launcher.ts` (subprocess wrapper)

**TS skeleton (launcher)**:
```typescript
import { spawn } from 'child_process';
import type { GenerationOptions } from './types';

export async function generateSyntheticPackages(opts: GenerationOptions): Promise<{ count: number; manifest: string }> {
  return new Promise((resolve, reject) => {
    const args = ['-m', 'apiary_train.data_prep',
      '--catalog', opts.catalogPath,
      '--benign-corpus', opts.benignCorpus,
      '--output', opts.output,
      '--multiplier', String(opts.multiplier ?? 8),
      '--seed', String(opts.seed ?? 42),
    ];
    const proc = spawn('python', args, { stdio: 'inherit' });
    proc.on('exit', code => code === 0 ? resolve(parseOutput(opts.output)) : reject(new Error(`exit ${code}`)));
  });
}
```

**Estimated hours**: 2-3h (subprocess wrapper) + 0.5h (catalog copy).

## Medium-impact ports

### 4. LLM Audit + Control Evidence Memo

**What apiary has**: `apiary_auditors/llm_audit.py` (459 LOC) with OpenAI/Ollama/Dwarfstar backends + 25%/75% prompt budget + Jinja2 memo template.

**Port destination**: `packages/worker/src/handlers/llm-audit.ts` + template directory.

**Dependencies**: `openai`, `node-fetch` (for Ollama), `handlebars` or `eta` for template.

**Estimated hours**: 16-20h (3 backends + template engine + integration with existing audit handler).

### 5. Bumblebee NDJSON bridge

**What apiary has**: `bumblebee_bridge/ingest.py` reads Bumblebee scanner output, scores via proxy, renders table.

**Port destination**: `packages/cli/src/commands/bumblebee.ts`.

**Estimated hours**: 3-4h.

### 6. Multi-ecosystem (PyPI + Composer)

**What apiary has**: 3 registry implementations + ecosystem-aware install-script policy + ctx/larvel demo incidents.

**Port destination**:
- `packages/api-proxy/src/registries/npm-registry.ts` (extract existing)
- `packages/api-proxy/src/registries/pypi-registry.ts` (new)
- `packages/api-proxy/src/registries/composer-registry.ts` (new)

**Estimated hours**: 16-24h (each ecosystem ~6-8h; PyPI metadata format + Composer Packagist API are well-documented).

## Stays in apiary (do not port)

### 7. H100 abliteration + SFT LoRA training

**Reason**: This is fundamentally a Python ML ecosystem (`transformers`, `peft`, `trl`, `torch`, `accelerate`). Porting to TS is wrong.

**Integration plan**: MW points its `MW_MODEL_ENDPOINT_BASE_URL` env var at the trained model's serving endpoint. apiary owns the training pipeline; MW consumes the resulting model.

**Estimated hours**: 1-2h (just config wiring).

### 8. Live demo runbook + incident replay

**Reason**: The demo IS the hackathon artifact. Keep in apiary repo, reference from MW README.

**Estimated hours**: 0h (cross-link only).

### 9. Insurance economics + pitch materials

**Reason**: These are hackathon-specific. Could move to `docs/hackathon/` in MW post-event, or stay in apiary and cross-link.

**Estimated hours**: 1-2h if cross-linking.

## Total time budget

| Priority | Item | Hours |
|----------|------|-------|
| **P0** | Source-match port | 12-16 |
| **P0** | Per-env policy port | 4-6 |
| **P0** | Attack catalog + generator copy | 2-4 |
| P1 | LLM audit + memo port | 16-20 |
| P1 | Bumblebee CLI port | 3-4 |
| P1 | Multi-ecosystem | 16-24 |
| P2 | H100 endpoint wiring | 1-2 |
| P2 | Demo cross-link | 0 |
| P2 | Pitch material cross-link | 1-2 |

**P0 only**: 18-26 hours (doable with 2 engineers in ~1.5 days).
**P0 + P1**: 53-74 hours (3-4 days with 2 engineers).
**Everything**: 55-78 hours plus integration testing.

## Pre-Sunday option: minimum cross-reference

If Andreas decides NOT to do any port pre-Sunday but wants MW to benefit from apiary's demo:

Add `EXTERNAL_DEMO.md` to apetersson/ModuleWarden:

```markdown
# External Demo - Zero-One Hack 2026

The Zero-One Hack Vienna 2026 submission for the UNIQA Insurance track is
hosted in a sibling repo:

- Repo: https://github.com/ademczuk/apiary
- Live landing: https://ademczuk.github.io/modulewarden-website/
- Demo runbook: https://github.com/ademczuk/apiary/blob/main/pitch/demo-runbook.md
- Capability comparison: https://github.com/ademczuk/apiary/blob/main/docs/CAPABILITY_MATRIX.md

apiary is the hackathon runtime. ModuleWarden is the production
architecture that absorbs apiary's working capabilities post-event.
The integration plan is in apiary's docs/ENHANCE_MODULEWARDEN.md.

Threat model and vocabulary (Class A/B/C, Verdict types, AuditContext,
Decision, Override) originate in this repo's docs/architecture.md and
were mirrored into apiary's shared/types.py.
```

**Estimated time**: 5 minutes.

## The decision

Pre-Sunday: do nothing or just the cross-reference. Post-event: prioritize P0 (source-match, per-env, attack catalog) in week 1. P1 over weeks 2-3. P2 as integration work permits.
