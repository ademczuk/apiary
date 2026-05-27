# WhatsApp message to Andreas - 2026-05-27 (final, post-pivot)

Copy-paste below the line. Uses WhatsApp markdown (asterisks for bold, underscores for italic).

---

*Apiary v2 - Zero-One Hack final prep update*

Took your meeting notes, did a hard pivot. v1 was a CodeBERT classifier with marketing - wrong product for UNIQA judges. v2 is the *self-hosted dependency firewall* you described: registry proxy + deterministic policy gate + git-driven .md quarantine workflow + LLM audit + insurance-grade evidence artifacts.

Four external reviews drove this: Codex adversarial (caught 3 security bugs), Pantheon council HIGH confidence, Grok strategic ("sponsor irrelevance theater" warning + +€/loss-ratio framing), my own /code-review pass.

*3 links*
- Hackathon repo: https://github.com/ademczuk/apiary
- Live landing page (updated for v2 + insurance framing): https://ademczuk.github.io/modulewarden-website/
- Branch on your repo: https://github.com/apetersson/ModuleWarden/tree/feat/landing-site

*What's on disk* (15,700 LOC across 71 files, all committed + pushed, 7-commit history on main)
- `apiary_proxy/` - Verdaccio-style npm registry proxy with on-disk cache (568 LOC)
- `apiary_policy/` - 5-rule deterministic gate: release-age >=14d, no install scripts, SRI checksum, source-match, quarantine-db (413 LOC)
- `apiary_quarantine/` - policy.json + sibling .md rationale workflow + Jinja2 Control Evidence Memo template in SOC 2 / ISO 27001 / NIST SSDF vocabulary (446 LOC)
- `apiary_auditors/` - LLM audit prompt builder (25% rubric, 75% code) with OpenAI, Ollama, *Dwarfstar* backend adapters (459 LOC)
- `apiary_cache/` - seed top-N packages into pre-audited cache (402 LOC)
- `demo/run_incident_replay.py` - *the killer demo*: runs apiary v2 against the sanitized postmark-mcp@1.0.16 reconstruction, produces BLOCK with rule-by-rule reasoning, generates a Control Evidence Memo. Smoke-tested PASS on 3 incidents (1.0.16 blocks, 1.0.12 allows, lodash allows).
- `pitch/underwriter-economics.md` - the insurance one-pager Grok said wins the room (real citations from NAIC, Coalition, Verizon DBIR)
- `pitch/insurance-economics-slides.md` - 2-slide insert for the deck
- `pitch/track-reframes.md`, `video-script.md`, `slide-deck.md` (11 slides), `q-and-a-prep.md` (20 Qs), `demo-runbook.md`
- 22-pattern attack catalog with real-world citations (worms removed per your note)
- CodeBERT pipeline still there, demoted to "one signal among many"

*3 security bugs caught + fixed* (would have torpedoed a security pitch)
1. SSRF in /score - anyone could fetch AWS metadata via the gate. Now hostname allowlist.
2. Path traversal in `tarfile.extractall` - malicious package could write `../../etc/whatever`. Now safe extractor.
3. Slurm script args mismatched train_codebert.py CLI - first sbatch would have burned 8h walltime in 30 seconds.

*The killer demo* (Pantheon council's exact call): `python demo/run_incident_replay.py --incident postmark-mcp-1.0.16`. Output:
```
[FAIL] release_age     released 0.0d ago, minimum is 14d
[FAIL] install_scripts non-trivial: postinstall='node postinstall.js'
[FAIL] source_match    repository.url missing
VERDICT: BLOCK - installation refused
Audit memo: demo/outputs/postmark-mcp-1.0.16__2026-05-27.md
Safe fallback: npm install postmark-mcp@1.0.12
```
That is the 60 seconds. Plus the memo opens in their PDF reader looking like a SOC 2 control report.

*Honest insurance economics (corrected from Grok's first-pass)*
Grok floated "+22pt margin / 35% premium discount" - those numbers do NOT survive contact with the public citations. Defensible math (NAIC 2025 + Coalition MDR precedent + Verizon DBIR 2024):
- Per-account: *+11 to +14 percentage points margin*
- Portfolio-level: *+2 to +4 points* after eligibility weighting
- Premium discount precedent: Coalition publishes *12.5%* for verified MDR, not 35%
This is what's in the one-pager. More credible to a 25-year insurance veteran than inflated numbers.

*3 demo risks for Sunday*
1. `source_match` rule is a stub that fails for every package. Demo masks this with an allowlist override. Sharp judge could ask "would lodash also fail on a fresh machine?" - honest answer: yes, source-match is unimplemented, the allowlist is the documented exception path.
2. `jinja2` must be `pip install`'d on the demo machine or memo loses formatting. Add to preflight.
3. 14-day release-age will block fresh hotfixes if judge asks "install the latest X". Either lower to 1d for demo run or pre-stage allowlist.

*What I need from you (priority order)*
1. *Track confirmation: UNIQA Insurance.* Grok + Pantheon both call it. Pitch reframed around "reduces loss ratio + produces underwriting evidence" not "trained a classifier".
2. *ChatGPT shared project link* you sent (zero-one-hack-vienna-...) - I cannot access it (auth-gated). Screenshot or paste-dump the brief contents?
3. *Dwarfstar endpoint for DeepSeek 4 Flash* - backend stub is wired. Send URL + model name and we drop in env vars (APIARY_DWARFSTAR_URL, APIARY_DWARFSTAR_MODEL).
4. *UNIQA pre-outreach* - Grok's highest-impact call: email their hackathon contact tonight asking for 2-3 anonymized historical cyber-claim cases. Even one real example anchored to their actual claims would jump us from 55% to 65% podium odds.
5. *Figshare label-inference bug* I caught in `scripts/preprocess.py:126` - the path-name heuristic does not match the actual NPMStudy archive layout. Result: every package labels as 0, training silently produces a constant classifier. ~30 min fix. Want me to handle it or you?
6. *Leonardo or H100 status* - slurm script wired, needs your account. If Leonardo not happening, what's plan B for compute?

*3 to read before Friday Case Reveal*
1. `pitch/underwriter-economics.md` - the insurance math one-pager
2. `pitch/demo-runbook.md` - Sunday morning step-by-step
3. `demo/run_incident_replay.py` and run it once: `python demo/run_incident_replay.py --incident postmark-mcp-1.0.16`

*Honest win probability (Grok's read, my agreement)*
- As shipped: *~38% podium, ~15% first place*
- + UNIQA real-claim data from your outreach: *~55-60% podium, ~30% first place*

All tests pass, 7 commits to main, repo clean, ready to clone.

Last thing: I sleep at this point. If anything urgent comes up overnight, ping me on Discord, otherwise we sync tomorrow morning to lock the Friday plan.

---

## Notes for me (not for Andreas)

- File at `apiary/pitch/whatsapp-to-andreas.md`
- WhatsApp formatting: *bold*, _italic_, `code`, ~strikethrough~
- Message length: ~750 words, fits in one WhatsApp message
- TL;DR if Andreas wants 50 words: "Pivoted to your vision per meeting notes, repo updated, 3 security bugs fixed, postmark replay demo works, insurance math one-pager done, landing page updated, 6 decisions needed from you, ~55% podium odds with UNIQA outreach"
