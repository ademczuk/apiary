# SUBMIT_APIARY.md - the case for shipping apiary Sunday

> Companion to `docs/ENHANCE_MODULEWARDEN.md`. Per-capability evidence + time-to-parity estimates.

## TL;DR

15 Sunday-demo-required capabilities. apiary owns 11. MW owns 2. Shared 2. Total hours for MW to reach apiary's Sunday-readiness: ~80-120 engineer-hours. We have ~30 hours of team capacity left before the 10:00 Sunday submission. **Submit apiary; port to MW post-hackathon.**

## Per-capability evidence

### 1. Working postmark-mcp@1.0.16 retroactive replay
- **apiary**: `demo/run_incident_replay.py:1-565` + `demo/incidents/postmark-mcp-1.0.16/` + golden-tested PASS
- **MW**: no incident replay equivalent
- **Time for MW to parity**: 8-12h
- **Verdict**: apiary

### 2. Control Evidence Memo (SOC 2 / ISO 27001 / NIST SSDF vocabulary)
- **apiary**: `apiary_quarantine/templates/control-evidence-memo.md.j2` + Jinja2 renderer
- **MW**: Decision type at `packages/shared/src/types.ts:24-38` but no rendered artifact for judges to OPEN
- **Time for MW to parity**: 4-6h
- **Verdict**: apiary

### 3. Insurance economics one-pager
- **apiary**: `pitch/underwriter-economics.md` with NAIC 2025 / Coalition MDR / Verizon DBIR 2024 citations + defensible +11-14pt margin math
- **MW**: no insurance positioning
- **Time for MW to parity**: 6-8h (research + writing, not a code port)
- **Verdict**: apiary

### 4. H100 abliteration + SFT LoRA training
- **apiary**: `apiary_train/*` (2,390 LOC) + slurm script + andreas-data adapter
- **MW**: nothing concrete; `docker-compose.yml` has LocalAI dev fallback, production defers to "external H100-backed infra"
- **Time for MW to parity**: not parity, integration. MW would subprocess apiary_train (~2h) or build native (40-60h)
- **Verdict**: apiary owns the H100 stack

### 5. 26-pattern attack catalog with real-world citations
- **apiary**: `data/patterns/attack-catalog.yaml` (1,500+ lines) covering Shai-Hulud, Lazarus, postmark-mcp, event-stream, ctx, larvel typosquat, plus 4 ecosystem-specific
- **MW**: threat categories named in `docs/architecture.md:14-38` (Class A/B/C) but no specific catalog
- **Time for MW to parity**: 12-16h (heavy research lift)
- **Verdict**: apiary

### 6. Per-environment policy tiers (dev/preprod/prod)
- **apiary**: `apiary_policy/environments.py:1-229` with concrete thresholds + YAML override loader
- **MW**: doesn't explicitly tier env policy in shipped TS
- **Time for MW to parity**: 6-8h
- **Verdict**: apiary, but MW could match quickly

### 7. Source-match against upstream repo
- **apiary**: `apiary_policy/source_match.py:1-520`, lodash 99% live test in 16.8s
- **MW**: in threat model doc but no implementation
- **Time for MW to parity**: 12-16h
- **Verdict**: apiary

### 8. Policy gate (release-age, install-scripts, checksum, source-match, quarantine-db)
- **apiary**: 5 rules in `apiary_policy/rules.py:1-358`
- **MW**: TASK-1.10 shipped in `packages/api-proxy/src/services/policy.ts` — read this file
- **Time to parity**: NONE — MW already has its own policy
- **Verdict**: both shipped; apiary's is closer to demo readiness because integrated with the live replay

### 9. Decision lineage / durability
- **apiary**: JSONL audit log only (acknowledged punt)
- **MW**: `packages/prisma-client/src/repositories/decisions.ts` + Postgres schema
- **Time for apiary to parity**: 8-12h to wire SQLite (not Postgres for hackathon)
- **Verdict**: **MW WINS**. apiary acknowledges and documents.

### 10. Per-job Docker audit isolation
- **apiary**: inline asyncio, NOT isolated
- **MW**: `packages/worker/src/services/container-runner.ts:1-315`
- **Time for apiary to parity**: 6-8h to wrap audits in `docker run`
- **Verdict**: **MW WINS**. apiary acknowledges and documents.

### 11. Admin override + Re-audit semantics
- **apiary**: `shared/types.py` has Override dataclass mirroring MW; NOT WIRED into policy
- **MW**: `packages/api-proxy/src/routes/admin.ts` + override repository, shipped
- **Time for apiary to parity**: 4-6h to wire
- **Verdict**: **MW WINS**, apiary acknowledges + mirrors vocabulary

### 12. Lockfile import + used-graph
- **apiary**: absent
- **MW**: `packages/api-proxy/src/services/lockfile-import.ts` (TASK-1.5)
- **Verdict**: **MW WINS**, out of scope for apiary's Sunday demo

### 13. Multi-ecosystem (PyPI + Composer)
- **apiary**: 3 registry impls + 4 ecosystem-specific attack patterns + ctx-0.2.2 PyPI incident
- **MW**: npm only in v1 plan
- **Time for MW to parity**: 16-24h
- **Verdict**: apiary

### 14. Live landing page
- **apiary**: `https://ademczuk.github.io/modulewarden-website/` with insurance vocabulary
- **MW**: `docs/site/index.html` (same file apiary upstreamed)
- **Verdict**: shared

### 15. Live demo runbook + asciinema backup + preflight checklist
- **apiary**: `pitch/demo-runbook.md` + `demo/record_backup.sh` + `pitch/preflight-checklist.md`
- **MW**: nothing
- **Time for MW to parity**: 2-3h (just the runbook; backup recording needs a working demo)
- **Verdict**: apiary

---

## Aggregate

- Sunday-required capabilities: 15
- **apiary owns**: 11 (1, 2, 3, 4, 5, 6, 7, 13, 15, plus 8 partial, plus 14 shared)
- **MW owns**: 4 (9 decision lineage, 10 Docker isolation, 11 admin override, 12 lockfile)
- **Total MW time-to-parity**: ~80-120 engineer-hours

We have ~30 hours of 2-person team capacity left before Sunday 10:00 submission. The math does not close on porting apiary's demo-critical work into MW pre-Sunday.

## Honest section: what MW wins

Don't pretend MW is weaker than it is. These are the items apiary will adopt post-hackathon:

- **Decision lineage with Prisma + Postgres** — apiary's JSONL is a punt; MW's relational schema with audit-runs / decisions / evidence / overrides / campaigns is the right model.
- **Per-job Docker isolation** — apiary runs audits inline. A motivated attacker with a malicious package could escape inline. MW's per-job container with no shared mutable state is the correct boundary.
- **Admin override semantics shipped** — apiary mirrored the Override type but didn't wire it. MW has the admin.ts routes + repository + audit trail.
- **pg-boss durable queue** — apiary uses asyncio. Crashes lose state. MW survives.
- **Lockfile import + subscription polling** — apiary has no lockfile flow. MW does (TASK-1.5).
- **Approved-only metadata filtering + dist-tag rewriting** — apiary proxies upstream directly. MW filters to only show approved versions, which is the right UX for developer trust.
- **Verdaccio promote-only architecture** — apiary has no backing artifact store. MW's Verdaccio + promote-only is the production-grade pattern.

These are the v2 production architecture apiary will port to AFTER the hackathon.

## The decision summary

Submit apiary Sunday because:
1. Live demo runs end-to-end NOW (postmark-mcp blocked, memo generated, smoke test PASS)
2. Insurance pitch landed (cited math, 12-slide deck, Q&A prep, demo runbook)
3. H100 training stack ready (rehearsal validates on Qwen 1.5B in 30min before burning H100 hours)
4. Multi-ecosystem coverage shipped (cross-stack defense story is the differentiator)
5. apiary already speaks MW's vocabulary (Class A/B/C, Verdict types, AuditContext, ThreatClass) so judges see continuity

Port to MW post-hackathon because:
1. MW's persistence story is correct
2. MW's audit isolation is correct
3. MW's verdict semantics are formalized
4. MW's TypeScript stack is the production target
5. Both architectures should converge into one product, with MW as the host
