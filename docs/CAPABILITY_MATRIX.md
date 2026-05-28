# Capability Matrix - apiary vs ModuleWarden

> Side-by-side comparison of capabilities with file:line citations in both repos.
> Written for cross-repo navigation by Andreas's Claude Code agent.

**apiary**: `C:\Projects\_Jobs\Collaborations\Andrew\apiary\` · github.com/ademczuk/apiary
**ModuleWarden**: `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone\` · github.com/apetersson/ModuleWarden (main)

| Legend | |
|---|---|
| **apiary** | row apiary owns / more complete |
| **MW** | row ModuleWarden owns / more complete |
| **both** | row both have at comparable depth |
| **absent** | row neither has, or one has only stub |

---

## 1. Threat Model + Vocabulary

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| Class A/B/C taxonomy | `CONSOLIDATION.md` references; `shared/types.py:14` | `docs/architecture.md:14-38` (canonical definition) | **MW** (origin) |
| Verdict types | `shared/types.py:13`, `apiary_policy/rules.py:39` | `packages/shared/src/types.ts:1` | both |
| AuditContext / PackageIdentity / Decision | `shared/types.py:23-71` (mirror) | `packages/shared/src/types.ts:1-38` (canonical) | **MW** (origin) |
| Override semantics | `shared/types.py:75-83` (placeholder, not wired) | `packages/api-proxy/src/routes/admin.ts` + repositories/overrides.ts | **MW** |
| Threat-class field in audit memo | `apiary_quarantine/templates/control-evidence-memo.md.j2` (renders threat_class) | absent (Decision type exists, no memo template) | **apiary** |

## 2. Registry Proxy Layer

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| npm metadata endpoint | `apiary_proxy/proxy.py` + `apiary_proxy/npm_registry.py` | `packages/api-proxy/src/routes/packument.ts` | both |
| npm tarball endpoint | `apiary_proxy/proxy.py` | `packages/api-proxy/src/routes/tarball.ts` | both |
| Approved-only metadata filtering | absent (we proxy upstream directly) | `packages/api-proxy/src/services/filter.ts` | **MW** |
| Dist-tag rewriting | absent | `packages/api-proxy/src/services/filter.ts` | **MW** |
| LRU cache eviction | `apiary_proxy/cache_lru.py` (200 LOC) | absent | **apiary** |
| SSRF allowlist | `modulewarden_gate/gate.py` (hostname allowlist) | not visible in current src | **apiary** |
| Path-traversal-safe tarball extract | `scripts/score_package.py` safe extractors | `packages/worker/src/services/container-runner.ts` (Docker boundary obviates) | both (different strategies) |
| PyPI registry | `apiary_proxy/pypi_registry.py` (NEW) | absent | **apiary** |
| Composer registry | `apiary_proxy/composer_registry.py` (NEW) | absent | **apiary** |

## 3. Policy Engine

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| Release-age rule | `apiary_policy/rules.py:check_release_age` | `packages/api-proxy/src/services/policy.ts` (TASK-1.10 shipped) | both |
| Install-script policy (allow/warn/deny) | `apiary_policy/rules.py:check_install_scripts` (ecosystem-aware) | `packages/api-proxy/src/services/policy.ts` | both |
| SRI / checksum verification | `apiary_policy/checksums.py` (128 LOC) | partial in policy.ts | **apiary** (dedicated module) |
| Source-match against upstream repo | `apiary_policy/source_match.py` (520 LOC, lodash 99% live test) | absent | **apiary** |
| Quarantine-db lookup | `apiary_policy/rules.py:check_known_quarantine` + `apiary_quarantine/workflow.py` | `packages/api-proxy/src/services/decisions.ts` (Prisma-backed) | both |
| Per-environment tiers (dev/preprod/prod) | `apiary_policy/environments.py` (229 LOC) | absent in current src | **apiary** |

## 4. Persistence + Durability

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| Decision storage | JSONL audit log (`apiary_proxy/proxy.py:121-128`) | Postgres via Prisma (`packages/prisma-client/src/repositories/decisions.ts`) | **MW** |
| Decision lineage (predecessor versions) | absent | `packages/prisma-client/prisma/schema.prisma:304-347` | **MW** |
| pg-boss durable jobs | absent (asyncio inline) | `packages/worker/src/jobs/queue.ts` (473 LOC) + tests (1397 LOC) | **MW** |
| Admin override persistence | absent | `packages/prisma-client/src/repositories/overrides.ts` | **MW** |
| Re-audit campaigns | absent | `packages/prisma-client/src/repositories/campaigns.ts` | **MW** |

## 5. Audit Execution Isolation

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| Per-job Docker container | absent (inline `asyncio.to_thread`) | `packages/worker/src/services/container-runner.ts` (315 LOC) | **MW** |
| RPC token scoping | absent | implied in container-runner.ts | **MW** |
| No-shared-mutable-state guarantee | weak (in-process state) | strong (one container per audit) | **MW** |
| Network capture / proxy | absent | planned in audit-runner image | **MW** (planned) |

## 6. LLM Audit Pipeline

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| Backend adapters (OpenAI/Ollama/Dwarfstar) | `apiary_auditors/llm_audit.py:321-560` (3 backends) | LocalAI fallback in docker-compose; production "external H100 infra" deferred | **apiary** |
| Prompt construction (25% rubric / 75% code) | `apiary_auditors/llm_audit.py:build_audit_prompt` | absent | **apiary** |
| Verdict accuracy + refusal-rate eval | `apiary_train/eval.py` (312 LOC) | absent | **apiary** |
| Private prompts + secrecy model | criteria file in repo (`apiary_auditors/criteria/default-criteria.md`) | `docs/architecture.md:90-118` (formal model) | **MW** (formal), **apiary** (impl) |

## 7. Training Infrastructure (the H100 story)

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| Abliteration (Failspy refusal-direction) | `apiary_train/abliteration.py` (388 LOC) | absent | **apiary** |
| SFT LoRA via trl.SFTTrainer | `apiary_train/sft_lora.py` (302 LOC) | absent | **apiary** |
| Multinode FSDP slurm for 64xH100 | `slurm/abliterate_then_sft.slurm` | absent | **apiary** |
| Rehearsal on Qwen2.5-Coder-1.5B | `apiary_train/rehearsal.py` (188 LOC) | absent | **apiary** |
| Synthetic data generator | `scripts/synthesize_data.py` (368 LOC) + injector.py (441 LOC) | absent | **apiary** |
| Attack pattern catalog | `data/patterns/attack-catalog.yaml` (26 patterns, 1500+ lines) | only categories in architecture.md | **apiary** |
| Figshare label inference | `scripts/preprocess.py` (ground-truth from sap_DT/) | absent | **apiary** |
| Andreas-data adapter (4 shapes) | `apiary_train/andreas_data_adapter.py` (276 LOC) | absent | **apiary** |

## 8. Multi-ecosystem Coverage

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| npm | yes | yes | both |
| PyPI | `apiary_proxy/pypi_registry.py` + `data/patterns/attack-catalog.yaml` pypi_* patterns + ctx-0.2.2 incident | absent (npm-only in v1 plan) | **apiary** |
| Composer / Packagist | `apiary_proxy/composer_registry.py` + composer_* patterns | absent (npm-only in v1 plan) | **apiary** |

## 9. Lockfile + Subscription

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| Lockfile import | absent | `packages/api-proxy/src/services/lockfile-import.ts` (TASK-1.5 shipped) | **MW** |
| Used-graph computation | absent | TASK-1.5 services | **MW** |
| Upstream subscription polling | absent | `packages/worker/src/handlers/audit.ts` (planned) | **MW** |
| Proactive new-version audit | absent | TASK-1.5 + worker integration | **MW** |
| Package diff (capability extract) | absent | `packages/shared/src/services/capability-extract.ts` + `package-diff.ts` | **MW** |

## 10. Insurance / Pitch Layer

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| Control Evidence Memo template (SOC 2 / ISO 27001 / NIST SSDF) | `apiary_quarantine/templates/control-evidence-memo.md.j2` | absent (Decision type exists, no rendered memo) | **apiary** |
| Insurance economics one-pager | `pitch/underwriter-economics.md` (NAIC/Coalition/Verizon cited, +11-14pt margin math) | absent | **apiary** |
| 12-slide pitch deck | `pitch/slide-deck.md` | absent | **apiary** |
| 20-question Q&A prep | `pitch/q-and-a-prep.md` | absent | **apiary** |
| Track reframes (UNIQA/Infineon/Sybilion) | `pitch/track-reframes.md` | absent | **apiary** |
| Live landing page | `https://ademczuk.github.io/modulewarden-website/` | `docs/site/index.html` (same file, contributed) | shared |
| Demo runbook | `pitch/demo-runbook.md` | absent | **apiary** |
| Preflight checklist | `pitch/preflight-checklist.md` | absent | **apiary** |
| asciinema backup recording script | `demo/record_backup.sh` | absent | **apiary** |

## 11. Live Demo Artifacts

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| postmark-mcp@1.0.16 retroactive replay | `demo/run_incident_replay.py` + `demo/incidents/postmark-mcp-1.0.16/` (golden-tested PASS) | absent | **apiary** |
| postmark-mcp@1.0.12 ALLOW baseline | `demo/incidents/postmark-mcp-1.0.12/` (golden-tested PASS) | absent | **apiary** |
| lodash@4.17.21 ALLOW baseline | `demo/incidents/lodash-4.17.21/` (golden-tested PASS) | absent | **apiary** |
| ctx@0.2.2 PyPI incident (May 2022) | `demo/incidents/ctx-0.2.2/` | absent | **apiary** |
| larvel/framework Composer typosquat | `demo/incidents/larvel-framework/` (stub) | absent | **apiary** |
| Smoke test harness | `demo/test_incident_replay.py` (3/3 PASS) | E2E test accepts 404/502/503 for tarball path | **apiary** |

## 12. Tests + Quality

| Capability | apiary | ModuleWarden | Winner |
|---|---|---|---|
| Unit test framework | pytest (40+ tests pass) | vitest (extensive worker + api-proxy + prisma + shared) | both |
| Policy tests | `tests/test_source_match.py`, `tests/test_environments.py`, etc. | `packages/api-proxy/src/__tests__/policy.test.ts` (TASK-1.10) | both |
| Smoke tests | `demo/test_incident_replay.py` (PASS) | proxy-e2e.test.ts (accepts failure codes) | **apiary** |
| Marker scan (anti-AI-marker) | enforced everywhere | not present | **apiary** |
| Type checking | minimal (type hints) | strict TS | **MW** |

---

## Summary

**apiary wins**: demo artifacts, H100 training stack, multi-ecosystem (PyPI + Composer), insurance pitch, Control Evidence Memo, source-match, per-env policy, attack catalog, LRU cache, andreas-data adapter.

**ModuleWarden wins**: persistence (Postgres + Prisma), durable job queue (pg-boss), per-job Docker isolation, admin overrides (shipped), re-audit campaigns, lockfile + subscription import, package-diff capability extraction, approved-only metadata filter, threat-model formalization (Class A/B/C origin).

**Both have**: npm proxy basics, policy engine (5 deterministic rules), verdict types, tests.

**Single biggest MW capability apiary cannot replicate by Sunday**: per-job Docker audit isolation. ~6-8h to wrap audits in `docker run` but introduces deploy complexity for a hackathon demo machine.

**Single biggest apiary capability MW cannot replicate by Sunday**: the H100 abliteration + SFT LoRA training stack. ~40-60h of Python ML work that fundamentally needs to stay in Python (transformers / peft / trl ecosystem) even if integrated into MW.
