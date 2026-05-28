# Andreas's plan (parsed from car-conversation braindump)

Date: 2026-05-28
Source: Andrew relayed a verbal braindump from Andreas while Andreas was driving. This is the structured interpretation.

## The methodology Andreas described

### One-shot classification on version diffs

- **Training pair**: unpatched (vulnerable) version of a CVE'd package = label malicious; patched (fixed) version = label benign
- **Train on the unpatched, test on the patched.** Counter-overfitting validation: proves the model learned the shape of malicious code rather than memorizing package names.
- **Model input**: `code + diff` between the two versions
- **Model output**: single one-shot classification verdict (malicious / benign / suspicious)
- **Alarm bell**: alert / notification when the verdict is malicious

### Data pipeline (he's already built most of it)

- **GHSA scrape**: shipped at `finetune/scripts/scrape-cases.mjs` with rate-limit hardening, npm packument enrichment, OSV cross-references, scraped-case.v1 schema
- **Target corpus**: ~4,000 vulnerabilities (GitHub authenticated rate limit is 5,000/hr; 4K leaves headroom)
- **Two output formats**:
  - **Raw format**: classification-head training (single-token binary verdict)
  - **Agentic format**: multi-turn instruction tuning for tool-use trajectory

### Two parallel work tracks

- **Track A - Finetune prep**: build training corpus, SFT a model, run baseline classification eval. apiary owns this naturally given the H100 abliteration + SFT LoRA stack.
- **Track B - Agentic run**: build the tool-use harness that wraps the model with file-read / shell / network-capture tools. Andreas owns this naturally given the per-job Docker container-runner he already shipped.

### The 2x2 (or 4-cell) evaluation matrix

|  | Vanilla model | Fine-tuned model |
|---|---|---|
| **One-shot prompt** | A | B |
| **Agentic harness (tools)** | C | D |

Minimum viable: A vs B (does fine-tuning help on this task?). Stronger: A/B/C or A/B/D as a third arm (is the agentic harness worth its latency + cost?). All four cells = the strongest research story.

This matrix is the differentiator at UNIQA. Underwriters ask "how much do I trust this thing?" - a model that classifies correctly without tools is cheap and durable; a model that needs tools to be right is operationally heavier but might catch novel cases.

## What apiary should cherrypick INTO ModuleWarden

| apiary asset | Why MW needs it | LOC |
|---|---|---|
| `apiary_train/abliteration.py` | Vanilla GLM/DeepSeek REFUSE to classify malicious code. Abliteration removes the refusal direction so the 2x2 matrix has working models, not refusing ones. | 388 |
| `apiary_train/sft_lora.py` | The fine-tune arm of the matrix. trl SFTTrainer + peft LoRA, FSDP-ready for 64xH100. | 302 |
| `apiary_train/scraped_case_adapter.py` | Already consumes his scraped-case.v1 JSONL into SFT format. The bridge. | 260 |
| `apiary_train/rehearsal.py` | Validates the pipeline on Qwen 1.5B in 30 min before burning H100 hours. | 188 |
| `apiary_auditors/llm_audit.py` | The "prepared prompt" mechanism (25 percent rubric / 75 percent code budget) for the one-shot classification arm. | 459 |
| `data/patterns/attack-catalog.yaml` | 26 attack patterns with real-world citations. Enriches prepared prompts with pattern primers. | 1500 lines |
| `slurm/abliterate_then_sft.slurm` | Multinode FSDP submit script for 64xH100. | 133 |
| `scripts/synthesize_data.py` + `data/patterns/injector.py` | Synthetic augmentation. Andreas's own note "needs a lot of synthetic data" matches this. 8x multiplier per benign baseline. | 800 |

Total cherrypick: roughly 4,000 LOC of working Python. Can drop into his `finetune/` directory OR run as a sibling Python service producing artifacts MW consumes at the model-endpoint boundary.

## What's MISSING in either repo and needs building tonight

1. **Code + diff extraction**: Andreas's scraper gives us advisory metadata, but not the actual source code or the differential between unpatched and patched versions. The model needs the CODE. apiary is building `apiary_train/version_pair_extractor.py` right now: fetch both tarballs from npm, safely extract, compute structural diff per file, emit raw + agentic training records.

2. **Eval matrix runner**: 2x2 or 4-cell evaluator with a shared held-out test set. Per-arm metrics: accuracy, F1, FPR (false-positive rate is the underwriter-relevant one), latency, cost. apiary is building `scripts/build_eval_matrix.py` to produce the test set + config; Andreas would need to run his side of the matrix.

3. **Agentic harness**: tool-using LLM loop for arms C/D. Andreas's `packages/audit-runner/` Docker is the natural sandbox; apiary's `apiary_auditors/llm_audit.py` is the prompt-construction layer.

## Real-world data inventory (where we are right now)

- GHSA: 100 cases pulled tonight (scraping more, target 1000-3000)
- OSSF malicious-packages: ~213K npm OSV records (currently being integrated)
- figshare NPMStudy: 13.5K labeled (6.5K malicious + 7K benign)
- Andreas's Drive folder: blocked on 401, awaiting permissions fix
- Synthetic: scriptable on demand (8x per benign baseline; ~50K already generated)

Total addressable real-world corpus: roughly 220-230K labeled records once OSSF integration completes.

## Open questions for Andreas

1. **The eval matrix arms** - is it 2 cells (A+B only) or 4 cells (A+B+C+D)? Different compute budgets.
2. **The model choice** - GLM 5.1 32B (his original ask), Llama 3.1 8B (Pantheon recommendation for the 36-hour clock), or DeepSeek 4 Pro 70B (tight)?
3. **Where to run the fine-tune** - apiary's slurm script targets 64xH100; if Leonardo is not happening what's the compute path?
4. **The Drive 401** - "Anyone with link" OR add joey.lucia OR push to his repo under finetune/corpus/
5. **golden-cases.json paths** - he has `finetune/corpus/golden-cases.json` referencing `finetune/examples/version-diff/audit-dossier.json` and `audit-report.json`. Those aren't in his checkout. Are they local-only, or is TASK-1.13 still in flight?
6. **Cherrypick acceptance** - does he want the 4K LOC apiary contribution dropped into his repo as a `finetune/` subdirectory, OR kept as a sibling apiary repo that MW invokes at the model-endpoint boundary?

## The pitch frame this enables

"Andreas built the production proxy + durable decision lineage + per-job Docker isolation + real-world GHSA data ingestion. Andrew built the live demo + H100 abliteration + SFT LoRA + insurance evidence pipeline. They compose at the model-endpoint boundary: his scraper feeds my training pipeline; my training output feeds his model endpoint. The 2x2 eval matrix proves out which configuration ships as the production audit pipeline."

That is a much stronger story for UNIQA judges than either repo alone.
