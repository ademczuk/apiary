# For Andreas's Agent (and Andreas)

> apiary is a hackathon-submission runtime built as a sibling to apetersson/ModuleWarden.
> This document is the entry point: orientation, evidence, decision framework.
> Optimized for an agent that will read the cited files before forming a view.

Audience: Andreas Petersson (GitHub: apetersson) and the Claude Code CLI agent he
points at this repo. The agent should read this top-to-bottom, then open the
files named in "Read these files first" before making any recommendation.

---

## TL;DR (60 seconds)

apiary is a working npm-registry-gate runtime built for the Zero-One Hack Vienna
2026 UNIQA Insurance track. It ships a live FastAPI proxy, a five-rule
deterministic policy engine, a real SHA256 source-match diff against upstream
git archives, an LRU tarball cache, three faithful incident replays with golden
smoke tests, an H100 abliteration plus SFT LoRA training stack, and an
insurance-grade Control Evidence Memo template. The honest read codex returned
yesterday: ship apiary Sunday because it is the only thing with a live demo
running end to end, then port its capabilities into ModuleWarden post-hackathon
because ModuleWarden's architecture is the better production target. apiary
adopted ModuleWarden's vocabulary (Verdict, PackageIdentity, AuditContext,
Decision, Threat Class A/B/C) on 2026-05-28 so judges see the same vocabulary
in both repos. The Sunday decision is whether to submit apiary as-is and port
afterward, or port apiary's demo plus training stack into ModuleWarden by
Saturday night. This document gives the agent what it needs to advise on that.

---

## Two repos, one product

### ModuleWarden (apetersson/ModuleWarden)

Andreas's backlog-first production architecture. TypeScript monorepo, Fastify
API proxy, Prisma plus Postgres for decision provenance, pg-boss for durable
jobs, Verdaccio as the backing store with promote-only semantics, per-job
Docker audit containers, PI in RPC mode for the agentic harness. As of
2026-05-28: 96 commits on main, 9,150 LOC of TypeScript, TASK-1.10 (verdict
policy plus admin override plus developer-safe status API) just shipped in
commit `bf45fd6`, TASK-1.16 (pg-boss orchestration) and TASK-1.6 (audit
runner) already landed.

Honest read on strengths:

- Threat model contract is explicit: Class A (compromised maintainer version
  bump, primary target), Class B (typosquatting, not optimized for), Class C
  (novel vulnerability discovery, pattern checks only). apiary did not have
  this until yesterday.
- Verdict semantics are clean: allow, block, quarantine plus admin overrides
  with scope (`SPECIFIC_VERSION`, `PACKAGE`, `PROJECT`, `GLOBAL`), reason,
  and `supersedesDecisionId`. The override and re-audit campaign vocabulary
  is the right shape for production.
- Prompt secrecy model is documented as a trust boundary. The audit prompts
  are server-side artifacts; the audit container never sees them; the client
  never sees them. This is the defensible thing about private agentic review.
- Decision lineage is real: `packages/prisma-client/src/repositories/decisions.ts`
  links a decision to its review job, evidence artifacts, predecessor hash,
  prompt versions, and supersedes pointer. This is what an SR 11-7 style
  model validator wants to see.
- Per-audit Docker isolation in `packages/worker/src/services/container-runner.ts`
  with no shared mutable state, run-scoped RPC tokens, and recorded-open
  egress as evidence. No prompts, no DB creds, no Verdaccio creds inside the
  audit container.

### apiary (ademczuk/apiary, this repo)

The hackathon runtime. Python, FastAPI, 22,521 LOC, 17 commits to main as of
this morning. Built to ship Sunday 13:30 against a live insurance-product
audience.

Honest read on strengths:

- Live demo works end to end. `python -m demo.run_incident_replay --incident
  postmark-mcp-1.0.16` blocks the malicious package, renders a Control
  Evidence Memo, fires the policy engine rule-by-rule, takes about 8 seconds.
  Three golden incidents replay cleanly: postmark-mcp 1.0.12 (clean prior),
  postmark-mcp 1.0.16 (malicious), lodash 4.17.21 (clean popular baseline).
- Real source-match. `apiary_policy/source_match.py` is 520 LOC of upstream
  git-archive download, tree extraction, SHA256 file comparison, and stem
  fallback for compiled output. Lodash live test yields 99% match (1048 of
  1049 files) in 16.8s. Earlier drafts of the README called this "deferred"
  but it shipped in commit `9fb21f1`.
- LRU cache eviction with disk quota at `apiary_proxy/cache_lru.py`. Mtime
  recency, configurable max bytes, sidecar `.cache-stats.json` for ops.
- Insurance-grade Control Evidence Memo template that renders via Jinja2 with
  a plain-text fallback that never fails to render. Rule table, score band,
  evidence references, threat class header, prompt-version footer.
- H100 training stack wired and rehearsable. `apiary_train/abliteration.py`
  implements Failspy refusal-direction orthogonalization (Arditi et al. 2024,
  arXiv:2406.11717). `apiary_train/sft_lora.py` runs LoRA SFT through
  `trl.SFTTrainer` plus `peft`, multi-node FSDP across 64 H100s.
  `apiary_train/rehearsal.py` validates the full pipeline on Qwen 1.5B in
  about 30 minutes on a single GPU before the H100 burn.
- Underwriter-economics one-pager grounded in NAIC 2024 loss ratios, Coalition
  MDR premium credit precedent, Verizon DBIR 2024 supply chain breach share,
  Sonatype malicious-package counts. Anchored numbers, citations at the
  bottom.

Honest read on gaps:

- Decision durability is JSONL with TTL eviction under `data/`, not Postgres.
- Audit work runs inline through asyncio, not in per-job Docker.
- Direct upstream proxy with cached tarballs, not Verdaccio with promote-only.
- `POST /-/v1/login` accepts anything. No production auth.
- No formal admin-identity-stamped overrides, no campaign re-audits triggered
  by prompt-version or model-profile changes. The `Override` dataclass exists
  in `shared/types.py` but is not wired.
- One-tenant deployment. Multi-tenant cache partitioning and policy overlays
  are not done.

---

## The Sunday decision

Two options. This is what Andreas's agent should help him weigh.

### Option 1: Submit apiary as-is, port to ModuleWarden post-hackathon

Cost: one weekend of focused demo polish on apiary. The live demo, the
Control Evidence Memo, the H100 training stack, the underwriter-economics
one-pager, and the three incident replays all stay where they are. The
WhatsApp consolidation note already credits ModuleWarden as the production
architecture target and frames apiary as the hackathon proof.

Pros:
- Demo works today. Three smoke tests pass. The 60-second judge-table flow is
  rehearsed in `pitch/demo-runbook.md`.
- The training stack is the most differentiated thing on the table. No other
  team will show abliteration plus SFT LoRA on a 32B-class model fine-tuned
  on figshare NPM malicious-package data plus a 50K synthetic example set
  generated from the 22-pattern attack catalog at `data/patterns/`.
- The insurance framing is anchored. Slide deck, Q&A prep, track reframes,
  underwriter economics, video script. All present in `pitch/`.
- No risk of breaking the demo by reworking it on Saturday.

Cons:
- Python plus JSONL is less polished than TypeScript plus Prisma plus Docker
  for a judge who reads the code. A sharp judge could grep
  `apiary_proxy/proxy.py:121-128` and call out the JSONL decision sidecar as
  not production-grade.
- The per-audit Docker isolation story is one we cannot tell from apiary
  alone. It is in ModuleWarden, not in this repo.
- Two repos at the judge table is a confusion vector. Need to be clean about
  which is the hackathon submission and which is the production target. The
  `CONSOLIDATION.md` doc handles that explicitly.

### Option 2: Port apiary's demo and training stack into ModuleWarden by Saturday

Cost: roughly 12-18 hours of focused work to translate the Python policy rules
to TypeScript, wire the H100 training output through the ModuleWarden audit
runner image, and write a TypeScript driver for the incident-replay flow that
calls into the Verdaccio backing.

Pros:
- One repo at the judge table. Cleaner submission story.
- Decision durability is Postgres from day one. Override and re-audit
  vocabulary is real, not a placeholder.
- Verdaccio promote-only is a stronger production posture than direct upstream
  proxy.
- Per-audit Docker isolation tells the prompt-secrecy story properly.

Cons:
- High risk of breaking the demo by Saturday night with no time to recover.
  The three incident goldens are tuned against the Python policy engine. Port
  bugs would surface late.
- The H100 training stack does not exist in ModuleWarden today. Folding
  `apiary_train/` into ModuleWarden's audit-runner image is non-trivial.
- Andreas's TASK-1.10 verdict policy plus admin override just landed in
  commit `bf45fd6`. Layering apiary's policy rules on top while TASK-1.10 is
  fresh introduces merge-conflict risk.
- The underwriter-economics one-pager and the slide deck reference apiary
  by name. Re-skinning takes an afternoon.

Recommendation framing for the agent: this is a judgment call about
demo-readiness versus production-architecture-readiness. The Sunday audience is
a UNIQA actuary or cyber product lead. They care about calibration,
explainability, and evidence quality. They do not care which repo the demo
runs from. The pragmatic call is Option 1 unless Andreas wants to invest the
Saturday hours to consolidate before judging.

---

## Read these files first

In this order. Annotated.

### Apiary repo

1. `C:\Projects\_Jobs\Collaborations\Andrew\apiary\pitch\whatsapp-andreas-consolidation.md`
   The codex adversarial review verdict, drafted as a WhatsApp message to
   Andreas. 76 lines. Contains the honest gap analysis, the five-item
   pre-Sunday consolidation diff that already shipped, and six decisions
   still in Andreas's court. Start here.

2. `C:\Projects\_Jobs\Collaborations\Andrew\apiary\CONSOLIDATION.md`
   The consolidation map. 161 lines. Says explicitly: apiary is the hackathon
   runtime, ModuleWarden is the production target. Lists what apiary borrows
   from ModuleWarden, what apiary punts on, and the post-hackathon merge
   plan. This is the document that frames the relationship for judges.

3. `C:\Projects\_Jobs\Collaborations\Andrew\apiary\shared\types.py`
   Python mirror of ModuleWarden's TypeScript vocabulary. 93 lines.
   `Verdict`, `ThreatClass`, `PackageIdentity`, `AuditContext`, `Decision`,
   `Override`. Same names, same semantics. Mirrored from
   `packages/shared/src/types.ts` in ModuleWarden.

4. `C:\Projects\_Jobs\Collaborations\Andrew\apiary\demo\run_incident_replay.py`
   The working demo. Fully offline. Three incidents in-tree under
   `demo/incidents/`. Read the docstring and the first 80 lines to see the
   flow.

5. `C:\Projects\_Jobs\Collaborations\Andrew\apiary\pitch\demo-runbook.md`
   The Sunday morning runbook. Literal step-by-step from clone to demo. Read
   the pre-flight checklist section first; it tells you what is supposed to
   pass before the pitch starts.

6. `C:\Projects\_Jobs\Collaborations\Andrew\apiary\README.md`
   Product framing. Read sections "Why this shape" and "What's NOT included".
   The latter is the honest gap list judges can verify.

7. `C:\Projects\_Jobs\Collaborations\Andrew\apiary\apiary_train\__init__.py`
   The training-stack overview docstring. Read this then peek at
   `abliteration.py` and `sft_lora.py` to verify the H100 pipeline is real.

8. `C:\Projects\_Jobs\Collaborations\Andrew\apiary\pitch\underwriter-economics.md`
   The insurance pitch one-pager. Premium tier math, loss ratio anchor, MDR
   discount precedent, Verizon plus Sonatype supply-chain numbers. Cited at
   the bottom.

### ModuleWarden clone (local)

The local clone is at `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone`.

1. `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone\README.md`
   Product framing for ModuleWarden. The threat model and Verdaccio-as-backing
   story.

2. `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone\docs\architecture.md`
   The implementation contract Andreas authored. Threat classification
   (Class A/B/C), core thesis (semantic diff against last allowed
   predecessor), prompt secrecy model, evidence model, verdict policy.
   Honored in apiary. This is the source-of-truth for the vocabulary.

3. `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone\packages\shared\src\types.ts`
   The canonical TypeScript types. apiary's `shared/types.py` mirrors this
   file. 103 lines.

4. `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone\packages\api-proxy\src\services\policy.ts`
   The policy engine that just shipped in TASK-1.10. 197 lines.
   `getEffectiveDecision` resolves admin-override-first-then-agent-decision
   with proper precedence.

5. `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone\packages\api-proxy\src\routes\admin.ts`
   The admin override endpoints. 165 lines. Scope levels, bearer-token auth,
   `supersedesDecisionId` lineage. This is the override vocabulary apiary
   needs to adopt.

6. `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone\packages\worker\src\services\container-runner.ts`
   The per-audit Docker isolation. 315 lines. Run-scoped RPC tokens,
   ephemeral temp workspaces, no shared mutable state, recorded-open egress.
   This is the cleaner production posture apiary punted on.

7. `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone\packages\prisma-client\src\repositories\decisions.ts`
   Decision lineage. 259 lines. Links a decision to review job, evidence
   artifacts, predecessor hash, prompt versions, supersedes pointer.

---

## What apiary has that ModuleWarden does not (today)

Specific. Verifiable.

- **A live registry proxy that gates installs end to end.**
  `apiary_proxy/proxy.py`. FastAPI app, metadata rewrite, cache lookup,
  policy invocation, audit log append. Run it on port 4873 and `npm
  install lodash` will hit it.
- **A real source-match implementation against upstream git archives.**
  `apiary_policy/source_match.py`, 520 LOC. Downloads upstream tarball,
  extracts both trees, SHA256 file comparison with stem fallback for
  compiled output. Live tested at 99% match on lodash in 16.8s.
- **Three faithful incident replays with golden smoke tests.**
  `demo/incidents/` has the postmark-mcp 1.0.12, postmark-mcp 1.0.16, and
  lodash 4.17.21 reconstructions. `demo/test_incident_replay.py` is the
  golden harness.
- **An insurance-grade Control Evidence Memo template.**
  `apiary_quarantine/templates/control-evidence-memo.md.j2`. Jinja2 with a
  plain-text fallback. Rule table, score band, threat class header,
  evidence references.
- **An H100 abliteration plus SFT LoRA training stack.**
  `apiary_train/`. Failspy refusal-direction orthogonalization,
  `trl.SFTTrainer` plus `peft` for LoRA, multi-node FSDP, slurm scripts.
  Rehearsal pipeline at `apiary_train/rehearsal.py` validates on Qwen 1.5B
  in 30 minutes before the H100 burn.
- **Three pluggable LLM audit backends.**
  `apiary_auditors/llm_audit.py`. OpenAI (`gpt-4o-mini`), Ollama (local
  `deepseek-coder:6.7b` or abliterated variant), Dwarfstar-style
  OpenAI-compatible endpoints.
- **The cache seeder that pre-audits popular packages.**
  `apiary_cache/seed.py`. Pre-audits top-N popular packages so the common
  case is a cache hit at install time.
- **LRU cache eviction with disk quota.**
  `apiary_proxy/cache_lru.py`. Background asyncio sweep, mtime recency,
  configurable max bytes.
- **A 22-pattern attack catalog used as training-data ground truth.**
  `data/patterns/attack-catalog.yaml`. The synthetic training corpus is
  generated from this catalog.
- **An underwriter-economics one-pager grounded in cited industry data.**
  `pitch/underwriter-economics.md`. NAIC 2024 loss ratios, Coalition MDR
  precedent, Verizon DBIR plus Sonatype supply-chain numbers.
- **A pitch deck plus Q&A prep plus track reframes plus video script.**
  Everything in `pitch/`. Three track reframes (UNIQA Insurance, Infineon
  Industry, Sybilion Forecasting) so the pitch lands on whichever brief gets
  revealed Friday.

---

## What ModuleWarden has that apiary does not (today)

Specific. Verifiable.

- **A formal threat-model contract document.**
  `docs/architecture.md`. Class A/B/C taxonomy, prompt secrecy boundaries,
  evidence model, verdict policy, network model. This is the document the
  whole product builds against.
- **Postgres plus Prisma for decision provenance.**
  `packages/prisma-client/`. Schema for decisions, evidence references,
  overrides, audit runs, prompt versions, model profiles. Migration history
  is real.
- **Admin overrides with scope, reason, supersedes pointer.**
  `packages/api-proxy/src/routes/admin.ts` plus
  `packages/api-proxy/src/services/policy.ts`. Override resolution beats
  agent decision; scope levels go from specific-version up to global; reason
  and `supersedesDecisionId` are mandatory.
- **A developer-safe status API.**
  `getStatusInfo` in `packages/api-proxy/src/services/policy.ts`. Returns
  effective verdict plus explanation plus next-action text without leaking
  prompts, scores, or internal evidence references.
- **Per-job Docker audit isolation.**
  `packages/worker/src/services/container-runner.ts`. Disposable containers,
  run-scoped RPC tokens, ephemeral workspaces, recorded-open egress.
- **pg-boss job orchestration with retry policy.**
  `packages/worker/` has the queue wrappers, dead-letter persistence,
  singleton-job dedupe, timeout-budget coverage. TASK-1.16 just landed.
- **Verdaccio promote-only backing.**
  Designed in `README.md` and reflected in the worker package. No install
  can resolve unless a promote happened. apiary proxies the upstream
  registry directly.
- **A re-audit campaign model.**
  Triggered by prompt-version or model-profile changes against the active
  used-graph. apiary has no equivalent.
- **A formal prompt-secrecy trust boundary.**
  `docs/architecture.md` section 4. Prompts are server-side artifacts; the
  audit container never sees them; the client never sees them. apiary
  stores prompts server-side under `apiary_auditors/prompts/` but the trust
  boundary is not formally documented.

---

## What we already adopted from ModuleWarden into apiary

The consolidation commit that landed on 2026-05-28 is
`86f25c3 feat(consolidation): adopt ModuleWarden threat-class taxonomy + verdict types`.

Adopted:

- **`Verdict` primitive** (`allow` / `block` / `quarantine`) - matches
  ModuleWarden exactly. Was already aligned; now also typed in
  `shared/types.py`.
- **`ThreatClass` taxonomy** (A / B / C) - stamped on the Control Evidence
  Memo and printed in the demo header.
- **`PackageIdentity` dataclass** - mirrors ModuleWarden field-for-field.
- **`AuditContext` dataclass** - mirrors ModuleWarden field-for-field.
- **`Decision` envelope** - mirrors ModuleWarden's `Decision` interface
  including `reasonSummary`, `promptVersions`, `modelProfile`, `scores`,
  `evidenceReferences`, `piSessionId`, `piRunId`, `actorType`,
  `predecessorVersion`, `predecessorHash`.
- **`Override` dataclass** - placeholder. Vocabulary is available; not yet
  wired into apiary's quarantine workflow.
- **Threat Class A framing on the demo header and the memo template.**
  postmark-mcp 1.0.16 is labeled as Class A in the replay output and the
  audit memo.

Not yet adopted, deliberately punted to post-hackathon:

- Prisma schema for decision durability (apiary uses JSONL with TTL).
- Per-job Docker audit isolation (apiary runs inline through asyncio).
- pg-boss for job orchestration (apiary uses asyncio).
- Verdaccio promote-only backing (apiary proxies upstream directly).
- Admin-identity-stamped overrides (apiary has quarantine plus rationale
  notes but no admin scope and supersedes pointer).
- Re-audit campaigns triggered by prompt-version or model-profile changes.
- Multi-tenant cache partitioning and policy overlays.

---

## The honest read on Sunday demo readiness

Per-capability table. Each row: shippable in apiary on Sunday? shippable in
ModuleWarden on Sunday? notes.

| Capability                          | apiary Sunday | ModuleWarden Sunday | Note                                                    |
| ----------------------------------- | ------------- | ------------------- | ------------------------------------------------------- |
| Live registry proxy                 | Yes           | Partial             | apiary proxy runs; MW has the routes but no end-to-end demo |
| Policy engine (deterministic rules) | Yes           | Yes                 | apiary has 5 rules in Python; MW has verdict policy in TS |
| Source-match against upstream git   | Yes           | No                  | apiary 520 LOC live-tested at 99% on lodash             |
| LRU cache eviction                  | Yes           | No                  | apiary `apiary_proxy/cache_lru.py`                      |
| Three incident replays (goldens)    | Yes           | No                  | apiary `demo/incidents/`                                |
| Control Evidence Memo               | Yes           | No                  | apiary Jinja2 template plus plain-text fallback         |
| H100 abliteration + SFT LoRA stack  | Yes           | No                  | apiary `apiary_train/` rehearsable on 1.5B in 30 min    |
| 22-pattern attack catalog           | Yes           | No                  | apiary `data/patterns/`                                 |
| Underwriter economics one-pager     | Yes           | No                  | apiary `pitch/underwriter-economics.md`                 |
| Postgres decision durability        | No            | Yes                 | MW Prisma schema; apiary uses JSONL                     |
| Admin override with scope           | No            | Yes                 | MW TASK-1.10 in `bf45fd6`                               |
| Per-job Docker audit isolation      | No            | Yes                 | MW `container-runner.ts`                                |
| pg-boss durable jobs                | No            | Yes                 | MW worker package                                       |
| Verdaccio promote-only              | No            | Designed            | MW spec; not wired end-to-end                           |
| Re-audit campaigns                  | No            | Partial             | MW pg-boss has the job type; campaign trigger not wired |
| Prompt-secrecy trust boundary doc   | Partial       | Yes                 | MW `docs/architecture.md` section 4 is the source       |
| Three pluggable LLM backends        | Yes           | No                  | apiary OpenAI, Ollama, Dwarfstar                        |
| Production auth on `POST /-/v1/login` | No          | Designed            | apiary stub accepts anything; MW spec'd not wired       |

Verdict: apiary wins on demo surface, training stack, and insurance pitch
artifacts. ModuleWarden wins on durability, isolation, overrides, and
architecture rigor. They do not overlap on most things. The fastest path to a
Sunday submission is to keep both repos as-is and ship apiary while citing
ModuleWarden in the consolidation document as the production target.

---

## How to interrogate this repo

Specific queries the agent can run to verify any claim in this document.
None of these mutate state.

### Verify the live demo claim

```powershell
cd C:\Projects\_Jobs\Collaborations\Andrew\apiary
python demo/run_incident_replay.py --incident postmark-mcp-1.0.16
```
Expected: a red BLOCK verdict, rule table with lifecycle-script failure, a
fresh Control Evidence Memo in `demo/outputs/`.

### Verify the smoke tests pass

```powershell
cd C:\Projects\_Jobs\Collaborations\Andrew\apiary
python demo/test_incident_replay.py
```
Expected: lodash ALLOW, 1.0.12 ALLOW, 1.0.16 BLOCK against the goldens.

### Verify the source-match implementation

```powershell
cd C:\Projects\_Jobs\Collaborations\Andrew\apiary
wc -l apiary_policy/source_match.py
```
Expected: about 520 lines. Read the file to confirm SHA256 comparison plus
stem fallback.

### Verify the H100 training stack is real

```powershell
cd C:\Projects\_Jobs\Collaborations\Andrew\apiary
type apiary_train\__init__.py
type apiary_train\abliteration.py | Select-Object -First 50
type apiary_train\sft_lora.py | Select-Object -First 50
```
Expected: docstring referencing Arditi et al. 2024, abliteration via
refusal-direction orthogonalization, `trl.SFTTrainer` plus `peft`.

### Verify the rehearsal pipeline runs

```powershell
cd C:\Projects\_Jobs\Collaborations\Andrew\apiary
python -m apiary_train.rehearsal --base-model Qwen/Qwen2.5-Coder-1.5B --quick
```
Expected: end-to-end run on a single GPU in about 30 minutes. Output
artifacts under `models/rehearsal-*`.

### Verify the consolidation vocabulary in the typed mirror

```powershell
cd C:\Projects\_Jobs\Collaborations\Andrew\apiary
type shared\types.py
```
Expected: `Verdict`, `ThreatClass`, `PackageIdentity`, `AuditContext`,
`Decision`, `Override` dataclasses. Mirrors
`_mw-clone\packages\shared\src\types.ts` field-for-field.

### Verify ModuleWarden's TASK-1.10 just shipped

```powershell
cd C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone
git log --oneline | Select-Object -First 10
```
Expected: `bf45fd6 feat: implement verdict policy, admin override endpoints,
and developer-safe status API` in the recent commits.

### Verify the codex review claim about the proxy E2E test

```powershell
cd C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone
Select-String -Path packages\api-proxy\src\__tests__\proxy-e2e.test.ts -Pattern "404|502|503" -Context 0,2
```
Expected: an assertion that the proxy is allowed to return 404, 502, or 503
for a tarball path. This is the test codex flagged as scaffold-stage.

### Verify the policy engine line count

```powershell
cd C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone
wc -l packages\api-proxy\src\services\policy.ts
```
Expected: 197 lines. Read it to see the override-then-decision resolution
order.

### Verify the underwriter math anchors

Read `apiary\pitch\underwriter-economics.md` and cross-check the references
list at the bottom. Specifically: NAIC 2024 (49% US cyber loss ratio),
Coalition (12.5% MDR premium credit), Verizon DBIR 2024 (15% supply-chain
breach share), Sonatype 2024 (512,847 malicious packages, 98.5% in npm).

---

## What this document deliberately leaves out

A roadmap of features apiary will add post-hackathon. The honest position is
that apiary is the hackathon runtime and ModuleWarden is the production
target. Putting a feature roadmap for apiary in this document would imply
apiary has a future as a standalone product separate from ModuleWarden, and
that is not the position the consolidation note takes. The post-hackathon
plan is the merge plan in `CONSOLIDATION.md` section "Post-hackathon
consolidation plan". That is the only forward-looking document the agent
should treat as canonical.

---

## A note on tone

This document is honest about apiary's gaps because Andreas is a real engineer
who will read the code. Marketing language would insult him. The numbers and
file paths above are verifiable; the agent should verify them before
recommending anything.

The relationship between the two repos is collaborative. apiary borrowed the
vocabulary; ModuleWarden gets the credit; the merge plan converges both onto
ModuleWarden's stack post-event. The Sunday submission is a deadline-driven
runtime, not a competing product. The architecture that ships to production
is Andreas's.
