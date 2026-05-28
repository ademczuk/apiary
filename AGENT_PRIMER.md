# AGENT_PRIMER.md - operating guide for LLM agents in this repo

> For any Claude Code agent (or other LLM-driven coding agent) operating on this repo.
> Read top-to-bottom on first invocation. Designed to be greppable.

## Repo map by purpose

| If you want to | Look in |
|----------------|---------|
| understand the hackathon submission strategy | `FOR_ANDREAS_AGENT.md`, `CONSOLIDATION.md` |
| see capability comparison with ModuleWarden | `docs/CAPABILITY_MATRIX.md` |
| understand WHY apiary not MW for Sunday | `docs/SUBMIT_APIARY.md` |
| understand the port-into-MW alternative | `docs/ENHANCE_MODULEWARDEN.md` |
| run the live demo | `demo/run_incident_replay.py --incident postmark-mcp-1.0.16` |
| see the policy engine | `apiary_policy/rules.py` |
| see the source-match impl | `apiary_policy/source_match.py` |
| see per-environment policy | `apiary_policy/environments.py` |
| see the proxy server | `apiary_proxy/proxy.py` |
| see multi-ecosystem registries | `apiary_proxy/{npm,pypi,composer}_registry.py` |
| see the LLM audit pipeline | `apiary_auditors/llm_audit.py` |
| see the H100 training stack | `apiary_train/` |
| see the attack catalog | `data/patterns/attack-catalog.yaml` |
| see the synthetic data generator | `scripts/synthesize_data.py` |
| see the Control Evidence Memo template | `apiary_quarantine/templates/control-evidence-memo.md.j2` |
| see the pitch materials | `pitch/` |
| see incident reconstructions | `demo/incidents/` |
| see the slurm script for H100 | `slurm/abliterate_then_sft.slurm` |
| see ModuleWarden vocabulary mirror | `shared/types.py` |

## Common agent tasks - which files to touch

| Task | Files to modify | Files to also update |
|------|-----------------|----------------------|
| Add a new policy rule | `apiary_policy/rules.py` | `apiary_policy/environments.py` (env tiers), `tests/test_*.py`, `docs/CAPABILITY_MATRIX.md` |
| Add a new attack pattern | `data/patterns/attack-catalog.yaml` | `tests/test_preprocess_labels.py` if it affects training labels |
| Add a new incident replay | `demo/incidents/{name}/` | `demo/test_incident_replay.py`, `demo/incidents/expected-outputs/` |
| Add a new LLM backend | `apiary_auditors/llm_audit.py` | `pyproject.toml` (deps), `pitch/q-and-a-prep.md` if pitch-relevant |
| Change vocabulary | `shared/types.py` | NEVER without checking ModuleWarden `packages/shared/src/types.ts` first |
| Add a new ecosystem | `apiary_proxy/{name}_registry.py` | `apiary_policy/rules.py` (ecosystem-aware policy), `data/patterns/attack-catalog.yaml` |

## What NOT to touch unless you understand consolidation context

- `shared/types.py` — mirrors ModuleWarden's TypeScript types in `packages/shared/src/types.ts`. Do not rename or restructure without updating both repos.
- `CONSOLIDATION.md` — describes the shipped consolidation diff. Update only after a new consolidation step.
- The threat-class taxonomy (Class A/B/C) — originates in ModuleWarden `docs/architecture.md:14-38`. Do not invent new classes.
- `pitch/slide-deck.md` — the pitch deck is the public-facing artifact. Changes should be reviewed.

## The demo flow

When `python demo/run_incident_replay.py --incident postmark-mcp-1.0.16` runs:

1. `demo/run_incident_replay.py:339` `run_incident()` is the entry point
2. Loads `demo/incidents/postmark-mcp-1.0.16/package.json` + `postinstall.js`
3. Builds a faux npm metadata blob (recent release time, no repository.url)
4. Calls `apiary_policy.rules.decide_policy()` with the metadata
5. Policy engine evaluates 5 rules (release-age, install-scripts, checksum, source-match, quarantine-db)
6. Returns `PolicyDecision` with verdict="block", failed_rules=["release_age", "install_scripts"]
7. Pretty-prints rule-by-rule pass/fail to stdout with "Threat class: A (Compromised-Maintainer Version Bump)" banner
8. Calls `apiary_quarantine.workflow.render_control_evidence_memo()` to generate the audit memo
9. Memo writes to `demo/outputs/postmark-mcp-1.0.16__{date}.md` formatted via `apiary_quarantine/templates/control-evidence-memo.md.j2`
10. Suggests safe fallback: `npm install postmark-mcp@1.0.12` (the legitimate predecessor)

## The training flow

When `sbatch slurm/abliterate_then_sft.slurm` runs:

1. **Stage 1 - Data prep** (1 CPU node, 15-45min): `python -m apiary_train.data_prep --figshare-archive ... --synthetic-dir ... --andreas-data ... --output data/sft/v1.jsonl`. Walks figshare ground truth + synthetic pattern injections + Andreas's adapted Drive data into instruction-tuning format.
2. **Stage 2 - Abliteration** (1 node, 8 H100, 30-90min): `python -m apiary_train.abliteration --base-model {GLM 5.1 / DeepSeek 4 Pro / Llama 3.1 8B} --output models/{name}-abliterated --harmful-prompts apiary_train/harmful_prompts.json --harmless-prompts apiary_train/harmless_prompts.json`. Failspy refusal-direction orthogonalization.
3. **Stage 3 - SFT LoRA** (8 nodes, 64 H100, 4-7h for 32B / 12-18h for 70B / ~3h for 8B): `accelerate launch ... -m apiary_train.sft_lora ...`. trl SFTTrainer with FSDP multinode.
4. **Stage 4 - Eval** (1 node, 1 H100, 20-45min): `python -m apiary_train.eval --model {name} --test-data data/sft/v1-test.jsonl`. AUROC + refusal-rate + per-pattern breakdown.

Pre-flight before sbatch: `python -m apiary_train.rehearsal --base-model Qwen/Qwen2.5-Coder-1.5B --quick` (30min on any 24GB GPU).

## Smoke test commands

```bash
# All Python compiles clean
python -m py_compile $(find . -name "*.py" -not -path './.git/*' -not -path '*/__pycache__*' -not -path './data/raw/*')

# Three-incident replay smoke test (must PASS)
python demo/test_incident_replay.py

# Full pytest suite
pytest tests/ -v

# YAML catalog loads
python -c "import yaml; print(len(yaml.safe_load(open('data/patterns/attack-catalog.yaml'))['patterns']))"

# Imports work without model
APIARY_MODEL_PATH=/nonexistent python -c "from modulewarden_gate.gate import app; print('ok')"
python -c "from apiary_proxy.proxy import app; print('ok')"
python -c "from apiary_policy.rules import decide_policy; print('ok')"
python -c "from apiary_quarantine.workflow import load_quarantine_db; print('ok')"
python -c "from apiary_auditors.llm_audit import build_audit_prompt; print('ok')"
python -c "from apiary_cache.seed import seed_from_top_packages; print('ok')"
```

## Marker scan (anti-AI-marker, required before any external-facing commit)

```bash
python -c "
import re, pathlib
banned_chars = {'em':'—','en':'–','ra':'→','la':'←','sq1':'‘','sq2':'’','dq1':'“','dq2':'”','el':'…'}
banned_critical = r'\b(comprehensive|delv(e|es|ing)|tapestry|realm|embark|leverag(e|ed|ing)|nuanced|holistic|seamless)\b'
hits = []
for p in pathlib.Path('.').rglob('*'):
    if not p.is_file() or '.git' in p.parts or '__pycache__' in p.parts or 'raw' in p.parts: continue
    if p.suffix not in {'.md', '.yaml', '.py', '.sh', '.toml', '.j2'}: continue
    try: text = p.read_text(encoding='utf-8')
    except: continue
    for name, ch in banned_chars.items():
        if ch in text: hits.append(f'{p}: char {name}')
    for m in re.finditer(banned_critical, text, re.I):
        ctx = text[max(0, m.start()-50):m.end()+50].lower()
        if any(s in ctx for s in ['banned','avoid','do not use','must avoid','must not','no \"']): continue
        hits.append(f'{p}: {m.group(0)!r}')
print('CLEAN' if not hits else 'HITS:\n' + '\n'.join(hits[:20]))
"
```

## Cross-repo navigation patterns

When investigating something, check the corresponding file in ModuleWarden:

| Investigating in apiary | Check in ModuleWarden (`_mw-clone/`) |
|-------------------------|-------------------------------------|
| `shared/types.py` | `packages/shared/src/types.ts` (canonical) |
| `apiary_policy/rules.py` | `packages/api-proxy/src/services/policy.ts` (his shipped TASK-1.10) |
| `apiary_proxy/proxy.py` routes | `packages/api-proxy/src/routes/{packument,tarball,admin,status}.ts` |
| `apiary_quarantine/workflow.py` | `packages/prisma-client/src/repositories/decisions.ts` |
| `modulewarden_gate/gate.py` audit log | `packages/prisma-client/src/repositories/audit-runs.ts` |
| `apiary_auditors/llm_audit.py` | not present (MW defers to external model endpoint) |
| `apiary_train/*` (H100 stack) | not present (stays in apiary) |
| `data/patterns/attack-catalog.yaml` | not present (MW only has Class A/B/C categories) |
| `pitch/*` | not present (hackathon-specific) |

## ModuleWarden clone state

- Path: `C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone\`
- GitHub: https://github.com/apetersson/ModuleWarden
- Default branch: `main` (NOT `feat/landing-site` — that's an old apiary contribution)
- Latest checkpoint: 96+ commits, ~9,150 LOC TypeScript, TASK-1.10 (verdict policy + admin override + status API) shipped

To refresh the clone:
```bash
cd C:\Projects\_Jobs\Collaborations\Andrew\_mw-clone
git checkout main && git pull origin main
```

## Style enforcement

- American English. Hyphens not em-dashes. No banned words (full list in CLAUDE.md style section).
- Marker-scan command above MUST return CLEAN before any commit touching external-facing text (README, slides, docs, pitch, WhatsApp briefs).
- File comments: single-line docstrings, no multi-paragraph blocks.
- Type hints on every public function.
- `pathlib.Path` not raw string paths.
- `logging` not `print()` except in CLI tools.

## When to ask the user vs proceed autonomously

- Architectural changes (new module, new service): ASK
- Style violations or simple bug fixes: PROCEED
- Cross-repo vocabulary changes: ASK (might affect ModuleWarden)
- Demo-critical changes: ASK if introducing risk; PROCEED if reducing it
- Pitch deck wording: ASK (public artifact)
- Training-script hyperparameters: PROCEED with rehearsal first
- New attack pattern in catalog: PROCEED with real citation
- Removing/punting a capability: ASK
