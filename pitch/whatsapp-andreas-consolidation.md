# WhatsApp message to Andreas - 2026-05-28 (post agent-readiness sprint)

Copy-paste below the line. WhatsApp markdown.

---

*Apiary v3 + agent-readability prep + multi-ecosystem*

Big round of work since the last update. Wrote everything in apiary in a form your Claude Code CLI agent can read and reason from. The agent's canonical entry point is `FOR_ANDREAS_AGENT.md` at the repo root. Point your CC at the repo and tell it to read that first.

*What landed in apiary (commits e36f563 + c904668)*

5 new agent-readable docs:
- `FOR_ANDREAS_AGENT.md` (553 lines): canonical entry, sibling-relationship framing, Sunday decision
- `CLAUDE.md`: lean operating context (Claude Code auto-loads this)
- `AGENT_PRIMER.md`: repo map, common tasks, smoke commands, cross-repo nav
- `docs/CAPABILITY_MATRIX.md`: 12-category side-by-side with file:line citations in BOTH repos
- `docs/SUBMIT_APIARY.md`: per-capability evidence + MW time-to-parity (~80-120h)
- `docs/ENHANCE_MODULEWARDEN.md`: concrete TS port plans + hour estimates (~55-78h)

Multi-ecosystem support (cross-stack defense story for the pitch):
- `apiary_proxy/registry.py` - Registry abstraction
- `apiary_proxy/npm_registry.py`, `pypi_registry.py`, `composer_registry.py`
- 4 new attack patterns: pypi_setup_py_exfil, pypi_dependency_confusion, composer_post_install_cmd, composer_typosquat (catalog now 26 patterns)
- `demo/incidents/ctx-0.2.2/` - PyPI May 2022 incident reconstruction (sanitized)
- `demo/incidents/larvel-framework/` - Composer typosquat of laravel/framework

Finetune-data adapter (ready for your Drive data):
- `scripts/fetch_andreas_data.py` - three-mode downloader (gdown/rclone/manual URL list)
- `apiary_train/andreas_data_adapter.py` - auto-detects 4 data shapes (chat messages, prompt+completion, input/output, HF splits)
- `apiary_train/data_prep.py` - `--andreas-data` flag wired into the SFT pipeline
- 7/7 adapter smoke tests PASS on synthetic samples

*Drive 401 - one ask*

I tried `gdown --folder https://drive.google.com/drive/folders/1GaNVt0eP9k-BW_E0fuIdqd5gsvY2a1Mz` and got HTTP 401. Folder permissions need to be "Anyone with the link" (currently "Restricted"). Alternatives if you do not want it public:
1. Share with `joey.lucia@gmail.com` directly (the auth I am using here)
2. Re-upload to a public folder
3. Paste the data into a gist / dump it in apiary/data/raw/andreas-finetune/ via your own workstation

Once we have access, `python scripts/fetch_andreas_data.py --drive-folder-id 1GaNVt0eP9k-BW_E0fuIdqd5gsvY2a1Mz --output data/raw/andreas-finetune/` pulls everything, the adapter auto-shapes it, and `data_prep.py --andreas-data` folds it into the SFT corpus for the H100 run.

*Honest recalibration on your repo*

I underestimated your shipped work on apetersson/ModuleWarden in the earlier briefs. After pulling main (was on a stale feat/landing-site checkout), the real picture: ~9,150 LOC TypeScript across 96 commits, TASK-1.10 verdict policy with admin override SHIPPED, decision lineage Prisma repos SHIPPED, container-runner.ts (315 LOC) for per-job Docker isolation SHIPPED, pg-boss queue (473 LOC) + 1397 LOC of job tests SHIPPED, lockfile-import service SHIPPED. That is not scaffolding; that is the production architecture. apiary's earlier briefs that called it "scaffolds" were wrong; the new docs correct it.

*The two paths your agent should weigh*

`docs/SUBMIT_APIARY.md` makes the case for shipping apiary Sunday (working demo + insurance pitch + H100 stack; MW would need 80-120h to reach apiary's Sunday-readiness across the 15 demo-required capabilities).

`docs/ENHANCE_MODULEWARDEN.md` makes the case for consolidating INTO ModuleWarden (concrete TS port plans with hour estimates; total ~55-78h for everything, P0-only ~18-26h). Pre-Sunday option: the 5-minute `EXTERNAL_DEMO.md` cross-reference in your repo pointing to apiary's demo URL, no code port needed.

*Honest split of who wins what*

apiary owns: working demo + Control Evidence Memo + insurance pitch + H100 abliteration+SFT + 26-pattern attack catalog + multi-ecosystem (npm + PyPI + Composer) + source-match + per-env policy + LRU cache + andreas-data adapter.

MW owns: Prisma decision lineage + per-job Docker isolation + pg-boss durable queue + admin override semantics + re-audit campaigns + lockfile + subscription import + approved-only metadata + Verdaccio promote-only + Class A/B/C threat model formalization (origin).

Sunday: ship apiary. Post-event: port apiary into MW with you as the canonical architecture host.

*What I still need from you*

1. Drive folder permissions fix OR alternative data delivery path
2. Accept the apiary collaborator invitation (https://github.com/ademczuk/apiary/invitations) - write access already granted
3. Model default for slurm (A=Llama 3.1 8B per Pantheon, B=GLM 5.1 32B per your original ask, C=defer to Friday)
4. Dwarfstar endpoint URL + model name for the inference path
5. UNIQA hackathon contact - any reply yet?
6. Your read on the SUBMIT vs ENHANCE decision (your CC agent can advise; I lean SUBMIT-apiary based on Sunday timeline math)

*Updated honest win probability*

- With current apiary state + multi-ecosystem: ~50-55% podium
- + UNIQA outreach landing one anonymized claim: ~58-62% podium
- + Sunday demo executes clean + we frame the abliteration in governance language not "uncensored model": ~62-68% podium

Repo: https://github.com/ademczuk/apiary (commit c904668) - 17 commits on main, all smoke tests PASS, marker scans clean.
Live site: https://ademczuk.github.io/modulewarden-website/.

---

## Notes for me (not for Andreas)

- File at `apiary/pitch/whatsapp-andreas-consolidation.md`
- Marker-clean
- ~700 words
- Tone: honest about my earlier underestimate of his repo, credits his shipped TASK-1.10 work explicitly, surfaces the Drive 401 as concrete blocker
- TL;DR for 30 sec: "5 agent-readable docs landed in apiary, multi-ecosystem ships, finetune adapter ready for your Drive data once you fix the 401, sibling-not-rival framing throughout, your CC agent reads FOR_ANDREAS_AGENT.md first."
