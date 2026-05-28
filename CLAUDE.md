# CLAUDE.md - apiary repo

## What this repo is

apiary is the Zero-One Hack Vienna 2026 UNIQA Insurance track submission runtime.
Sibling repo to apetersson/ModuleWarden. Andreas built the production architecture
in ModuleWarden (~9,150 LOC TypeScript, TASK-1.10 verdict policy shipped). apiary
is the hackathon demo + training pipeline + insurance pitch.

## Read these first (in order)

1. `FOR_ANDREAS_AGENT.md` - canonical entry point with TL;DR and Sunday decision framework
2. `CONSOLIDATION.md` - apiary/ModuleWarden capability mapping shipped 2026-05-28
3. `docs/CAPABILITY_MATRIX.md` - file:line citations of every capability in both repos
4. `docs/SUBMIT_APIARY.md` - evidence for the submit-apiary path
5. `docs/ENHANCE_MODULEWARDEN.md` - evidence for the port-into-ModuleWarden path
6. `AGENT_PRIMER.md` - repo navigation reference

## Operating constraints

- ModuleWarden's TypeScript types in `packages/shared/src/types.ts` are the canonical vocabulary. apiary mirrors them at `shared/types.py`. Do not introduce divergent names.
- The Class A/B/C threat taxonomy from ModuleWarden `docs/architecture.md` is the canonical model. apiary uses it in audit memos and demo banners.
- The hackathon demo is `demo/run_incident_replay.py`. Smoke tests at `demo/test_incident_replay.py` must pass.
- When in doubt about a vocabulary choice: stay aligned with ModuleWarden's types.
- New capabilities: document in `docs/CAPABILITY_MATRIX.md`.
- Hackathon-demo-critical changes: update `pitch/demo-runbook.md`.
- H100 training stack changes: smoke-test `apiary_train.rehearsal`.

## Style

American English. No em-dashes. No banned words: comprehensive, leverage, nuanced, holistic, seamless, tapestry, realm, embark, journey, vibrant, unveil, crucial, delve, certainly, notably, moreover, navigate.

## Cross-repo

- ModuleWarden GitHub: https://github.com/apetersson/ModuleWarden
- apiary GitHub: https://github.com/ademczuk/apiary
- Local ModuleWarden clone: `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone\` (checkout main)
- Live landing page: https://ademczuk.github.io/modulewarden-website/

## The Sunday decision (the single most important context)

Codex adversarial review verdict, validated by Pantheon council: **submit apiary Sunday because it has the only working demo + insurance pitch + H100 training stack**. Port apiary's capabilities into ModuleWarden post-hackathon because ModuleWarden's architecture (Prisma decision lineage, per-job Docker, admin overrides, pg-boss queues) is the better production target.

If you (the reader, agent or human) want to override this verdict, read `docs/CAPABILITY_MATRIX.md` first to see file:line evidence on both sides.
