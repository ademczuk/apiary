# WhatsApp message to Andreas — 2026-05-27

Copy-paste below the line. Uses WhatsApp markdown (asterisks for bold, underscores for italic).

---

*Apiary v2 — Zero-One Hack prep update*

Took your meeting notes, pivoted the architecture. v1 was a CodeBERT classifier with a marketing site — wrong product for UNIQA judges. v2 is the *self-hosted dependency firewall* you described: artifactory + policy gate + quarantine + LLM audit. Three external reviews (Codex adversarial, Pantheon council HIGH confidence, Grok strategic) all converged on the same pivot.

*3 links*
- Repo: https://github.com/ademczuk/apiary
- Live marketing site: https://ademczuk.github.io/modulewarden-website/
- Branch on your repo: https://github.com/apetersson/ModuleWarden/tree/feat/landing-site

*What's on disk* (all committed + pushed, 4-commit history)
- `apiary_proxy/` — Verdaccio-style npm registry proxy with on-disk cache, returns 200/451/202 with informative bodies (568 LOC)
- `apiary_policy/` — 5-rule engine: release-age ≥14d, no install scripts, SRI checksum, source-match, quarantine-db lookup (413 LOC)
- `apiary_quarantine/` — policy.json with sibling .md rationale workflow + add/promote/validate CLI (336 LOC)
- `apiary_auditors/` — LLM audit prompt builder (25% rubric / 75% code budget) with OpenAI, Ollama, *Dwarfstar* backend adapters (459 LOC + default-criteria.md)
- `apiary_cache/` — seed top-N packages into pre-audited cache (402 LOC)
- `pitch/` — 60-sec video script, 11-slide deck, 20-question Q&A, UNIQA-specific track reframe, Sunday-morning demo runbook
- 22-pattern attack catalog (worms removed per your "worms not applicable" note)
- CodeBERT pipeline still there, *demoted to "one signal among many"* not the centerpiece

*3 security bugs caught + fixed* (would have been embarrassing for a security product)
1. SSRF in /score — anyone could have used the gate to fetch AWS metadata or internal services. Now hostname allowlist (registry.npmjs.org, yarnpkg).
2. Path traversal in `tarfile.extractall` — malicious package could write `../../etc/whatever`. Now safe extractor rejects abs paths, `..`, symlinks.
3. Slurm script args didn't match `train_codebert.py` CLI — first sbatch would have burned 8h walltime in 30 seconds.

*3 demo risks for Sunday*
1. `source-match` rule is a stub that always quarantines. Pre-stage demo packages with `apiary-quarantine add ... --state allowlist`.
2. 14-day min release age will block fresh hotfixes if a judge asks "install the latest X". Either lower `--min-age-days 1` for the demo run, or pre-stage.
3. Audit-on-seed of 2,000 packages takes hours. Seed without audit first (`--audit-backend none`), then audit only the ~30 demo packages.

*What I need from you*
1. *Track confirmation: UNIQA Insurance.* Grok + Pantheon both call it. Reframe pitch around "reduces loss ratio + produces underwriting evidence" not "trained a classifier".
2. *ChatGPT shared project link* you mentioned (zero-one-hack-vienna) — I can't access it (auth-gated). Screenshot or paste the brief?
3. *Dwarfstar endpoint for DeepSeek 4 Flash* — backend stub is wired. Send URL + model name and I'll plug in env vars (APIARY_DWARFSTAR_URL, APIARY_DWARFSTAR_MODEL).
4. *UNIQA pre-outreach* — Grok's highest-leverage call: email their hackathon contact tonight asking for 2-3 anonymized historical cyber-claim cases. Even one real example anchored to their actual claims would make the demo land at the judges' table.
5. *Figshare label-inference bug* I found in `scripts/preprocess.py:126` — the path-name heuristic doesn't match the actual NPMStudy archive layout (it has `cleaning/false_negative`, `selected_benign_packages.txt`, `package_label/`). Result: every package labels as 0, training silently produces a constant classifier. ~30 min fix. Want me to handle it or you want it?
6. *Leonardo / H100 status* — slurm script is wired, but needs your account. If Leonardo isn't happening, what's plan B for compute?

*3 to read before Friday Case Reveal*
1. `pitch/track-reframes.md` — UNIQA framing leads, alternates for Infineon + Sybilion
2. `pitch/demo-runbook.md` — Sunday-morning step-by-step
3. `README.md` — if the v2 framing doesn't ring true to your vision, that's the first thing to fix

*The killer demo moment* (Pantheon council's call, also matches your "quarantine + .md when update json" notes): developer runs `npm install suspicious-package`, the proxy quarantines it in real time with a human-readable reason chain + an audit memo (.md), and offers a safe fallback to the cached approved version. 60 seconds. Rehearse to muscle memory.

All tests pass, repo clean, ready for you to clone.

---

## Notes for me (not for Andreas)

- Saved at `apiary/pitch/whatsapp-to-andreas.md` for reference + future updates
- WhatsApp formatting: *bold*, _italic_, `code`, ~strikethrough~
- If Andreas wants the long version (this is ~600 words), it fits in one WhatsApp message
- If he wants shorter, the TL;DR is: "pivoted to your vision, repo is at the URL, three security fixes shipped, need decisions on 6 items"
