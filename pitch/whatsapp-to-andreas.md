# WhatsApp message to Andreas - 2026-05-28 (post H100 v3 stack)

Copy-paste below the line. Uses WhatsApp markdown (asterisks for bold, underscores for italic).

---

*Apiary v3 - H100 training stack landed*

Three big things since the last update.

*1) v3 training stack is in*

`apiary_train/` module shipped: abliteration (Failspy refusal-direction orthogonalization), SFT LoRA via trl.SFTTrainer + peft, eval with verdict accuracy + refusal-rate + AUROC, rehearsal pipeline that runs end-to-end on Qwen2.5-Coder-1.5B in 30 min for pre-flight, multinode slurm script for 64x H100 distributed.

Wall-clock estimates from the build agent:
- *GLM 5.1 32B on 64x H100*: data prep 15-45min + abliteration 30-90min + SFT 4-7h + eval 20-45min = *6-9h total*. Inside the 36h budget with room for one re-run.
- *DeepSeek 4 Pro 70B*: roughly double, *12-18h total*. Tight, consider 4-bit base load.
- *Llama 3.1 8B / Mistral 7B*: single-node 8x H100, ~13h total.

CodeBERT classifier still in repo as the deterministic backup signal, demoted but not deleted.

*2) Pantheon council pushed back on the 32B/70B plan*

I asked Pantheon council for a brutal review before kicking off the build. Verdict (MEDIUM confidence, 2 reviewers + chairman): *recommend Llama 3.1 8B abliterated, not 32B GLM or 70B DeepSeek*.

Their three points worth knowing:

- *13K real examples is thin for 32B even with LoRA.* Need 1:2 to 1:4 synthetic ratio to avoid overfit. For 7B/8B, 13K real + our existing 50K synthetic is enough.
- *"Abliteration" is a PITCH LIABILITY for UNIQA judges*, not an asset. Cyber-insurance underwriters hear "uncensored model" as "weak governance / compliance risk". Don't say "removed refusal vectors". Say: *"domain-specialized security-analysis model running inside a governed pipeline with deterministic pre-filters, schema-constrained outputs, audit logs, human review."* Same fact, very different reception.
- *Multi-node NCCL collapse is the killer on 70B*, not the math.

I built ALL THREE configs (`sft_config_glm.yaml`, `sft_config_deepseek.yaml`, plus the 8B-ready default) so we can pick at sbatch time. The slurm scripts are model-agnostic.

*3) Build agent's "if you must cut one thing, cut abliteration" advice*

Counterintuitive but agent argues: coder-base models don't have heavy RLHF refusal cascades anyway. Failing to abliterate costs 5-15% verdict accuracy on edge cases. Failing to SFT costs the entire task. Skip the abliteration stage to reclaim 30-90min + remove a whole class of "layer resolution failed" failure modes.

*Your call: which model do we default the slurm script to?*

- *A: Llama 3.1 8B abliterated* - Pantheon's recommendation, safest, leaves 64-GPU headroom for parallel eval and synthetic data generation
- *B: GLM 5.1 32B abliterated* - your original ask, runnable in 6-9h on 8 nodes, no buffer for mistakes
- *C: All three configs, you decide Friday based on case-reveal scope*

I defaulted to *C* in the slurm script comments - uncomment the right line at submit time. Tell me if you want a different default and I'll repoint.

*Pre-flight before sbatch (do this on the dev machine Saturday morning)*

```
python -m apiary_train.rehearsal --base-model Qwen/Qwen2.5-Coder-1.5B --quick
```

Runs the full pipeline end-to-end on a 1.5B model. ~30 min on any 24GB GPU. Catches the most likely "layer resolution / tokenizer / FSDP wrapping" failure modes before burning H100 hours.

*Other things landed this round*

- *Real source-match rule* (not the stub) - fetches upstream repo archive, file-by-file SHA256 compare, 95% match threshold. Lodash live test: 99% match in 16.8s.
- *Per-environment policy tiers* - dev (warn-only, age 0d, scripts allowed), preprod (age 7d, scripts denied), prod (age 14d, scripts denied, source-match required).
- *LRU eviction* on the proxy tarball cache (10GB default, mtime-based, background asyncio sweep).
- *Figshare label-inference fix* - the path heuristic was failing on the real archive layout. Found correct ground-truth at `ToolDetection/DetectionResults/sap_DT/`: 7,024 benign + 6,571 malicious = 13,595 labeled. Cross-agent bridge `scripts.preprocess.infer_label()` added so v3 data_prep can use them.
- *Bumblebee v2 bridge* - rewired from old v1 gate to new proxy endpoint. Smoke test: 1 BLOCK for postmark-mcp@1.0.16, 7 ALLOW for benign. CI gate exit code works.
- *Test goldens regenerated* for the new source-match SKIPPED behavior. All three incident replays PASS.
- *apetersson invited to ademczuk/apiary as write-access collaborator* (invitation 320392839, accept at https://github.com/ademczuk/apiary/invitations). FYI: your own ModuleWarden repo pushed 2h ago with lockfile import + subscriptions + proactive upstream auditing + isolated Docker audit runner work. We're convergent, not divergent.

*Critical caveat on figshare data*

The 88MB archive we downloaded has labels for 13,595 packages but actual `package.json` files for only 636 (all in `Data/cleaning/false_negative/`). The other 14K reference packages in `unzip_malware/` / `unzip_benign/` directories that need either:
- the full 3.4GB archive download (`scripts/download_figshare.py --full`)
- OR re-downloading via the dataset's `Data/collection/package_download.py`

If you're starting the H100 run Saturday, kick off the 3.4GB download Friday night so the SFT job has actual training material.

*Updated honest win probability*

- As shipped pre-H100-stack: ~38% podium
- *Now with v3 training infra*: ~45-50% podium IF the SFT run completes cleanly + we frame the model as "domain-specialized security analyst" not "abliterated"
- *+ UNIQA real-claim outreach landing*: ~55-60% podium
- *+ Sunday demo executes without surprises*: ~60-65% podium / ~30% first place

*Decisions I still need from you*

1. Model default for slurm? (A/B/C above)
2. Did the 3.4GB figshare archive get downloaded yet? Andreas needs to kick this off Friday night at latest
3. Dwarfstar endpoint for DeepSeek 4 Flash for the inference path - URL + model name, drop in `APIARY_DWARFSTAR_URL` / `APIARY_DWARFSTAR_MODEL` env vars
4. UNIQA outreach - any reply from their hackathon contact?
5. The ChatGPT shared project link (zero-one-hack-vienna-...) brief - screenshot or paste?
6. Accept the collaborator invitation on ademczuk/apiary

Repo is at https://github.com/ademczuk/apiary, 12 commits to main, all CI clean. Live landing page at https://ademczuk.github.io/modulewarden-website/.

I'm at the natural sleep break. Ping me on Discord if anything urgent overnight; otherwise we sync morning to lock the Saturday plan.

---

## Notes for me (not for Andreas)

- File at `apiary/pitch/whatsapp-to-andreas.md`, marker-clean
- ~900 words, longer than ideal but the situation has compounded a lot of decisions
- TL;DR if he wants 30s: "H100 v3 training stack landed (abliteration + SFT LoRA for GLM/DeepSeek/8B on 64xH100, 6-9h for 32B, all model-agnostic). Pantheon recommends 8B not 32B for safety. 6 decisions needed. Accept the apiary collab invite."
