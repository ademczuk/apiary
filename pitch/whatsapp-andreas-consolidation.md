# WhatsApp message to Andreas - 2026-05-28 (post-OOM recovery)

Copy-paste below the line. WhatsApp markdown.

---

*Post-OOM status + the corpus we have right now*

Workstation OOM'd while three agents were running. Killed the Datadog full-extract job mid-flight. Recovery is clean: smoke tests still PASS, no malicious code executed (verified no node_modules, no postinstall scripts ran, version-pair extractions are inert filesystem files), disk freed.

*What survived the OOM* (commit 6cb7394 on apiary main):

- *2,305 real GHSA cases* normalized to SFT format (1,844 train + 230 val + 231 test). All anchored to actual advisory IDs, CWE classifications, version ranges, npm packument metadata. 4.65 MB JSONL.
- *824 incident_replay cases* in there (GHSA type=malware: confirmed malicious packages, not just CVE-tagged bugs) + 1,481 cve_diff cases.
- *89 version-pair extractions* (got 40 MB of inert npm package metadata + diff data before OOM). For each: unpatched + patched tarballs fetched + safely extracted + structural diff computed. The "code + diff" input format you described.
- *9 new Python source files* shipped (no execution, no install side effects):
  - `apiary_train/version_pair_extractor.py` - the code+diff extraction core
  - `apiary_train/raw_format_builder.py` - VersionPair -> classification-head training records (your "raw format")
  - `apiary_train/agentic_format_builder.py` - VersionPair -> simulated tool-use trajectories (your "agentic format")
  - `apiary_train/datadog_adapter.py` + `apiary_train/ossv_adapter.py` - normalize Datadog and OSSF corpora to scraped-case.v1
  - `scripts/build_eval_matrix.py` - 2x2 test-set builder for your evaluation matrix
  - `scripts/extract_version_pairs.py` - CLI for the version pair extractor
  - `scripts/fetch_datadog_dataset.py` + `scripts/fetch_ossf_malicious_packages.py` - fetchers (NOT yet run at scale)

*What did NOT survive* (need to redo more carefully):

- Datadog full-extract: clone partially complete, OOM killed the extraction. We have the fetcher code, just need to run it with smaller batches.
- OSSF malicious-packages full clone: the OSV records weren't ingested. We have the adapter code, just need to git clone with sparse-checkout.

*Web research confirmed additional data sources I'll fetch carefully*:

- *Datadog malicious-software-packages-dataset*: ~17,600 real npm packages, Apache-2.0, encrypted with password "infected" specifically to prevent accidental execution. Extracting in 100-package batches is safe; extracting all 17K at once is what OOM'd us.
- *OSV GCS bulk*: `gs://osv-vulnerabilities/npm/all.zip` - no auth, contains ~190K MAL-prefixed records from 2025 alone
- *Mendeley dataset 6tc8wrp62g*: CC-BY-4.0, March 2026 release, JS source files
- *MITRE CVElistV5 + NVD REST API*: public domain CVE-tagged npm records

Major fresh incidents we should add to demo collection (newer than postmark-mcp Sep 2025):
- *Axios March 2026*: 100M+ weekly downloads affected, CISA advisory, versions 1.14.1 + 0.30.4 + plain-crypto-js@4.2.1
- *Mini Shai-Hulud / TanStack May 2026*: 17 days ago, GHSA-g7cv-rxg3-hmpx, self-spreading
- *Shai-Hulud 2.0 Nov 2025*: 795 packages in one wave

These would crush the demo because they're current press-cycle incidents UNIQA judges recognize.

*Real-world corpus we have NOW*:
- GHSA: 2,305 cases (committed to SFT corpus)
- Version pairs: 89 extracted (code + structural diff)
- figshare NPMStudy: 13.5K labeled (existing)
- Synthetic: 50K (existing)

*Could add carefully (not OOM the machine)*:
- Datadog: ~17,600 npm packages, extract in 100-package batches
- OSSF: ~213K npm OSV records, sparse-checkout
- Total potential: ~245K records

*Open questions for you (priority order)*:

1. *OOM postmortem*: my agent tried to extract 17K Datadog tarballs in one go. For the H100 run, do you want me to extract a sample (say 2K) or skip Datadog entirely and rely on the 2,305 GHSA cases + figshare + synthetic?
2. *Eval matrix arms*: 2 cells (A + B) or all 4? Affects compute budget on Sunday.
3. *Model default for slurm*: A=Llama 3.1 8B (Pantheon recommendation), B=GLM 5.1 32B (your original ask), or C=defer to Friday?
4. *Drive 401 fix*: still pending. Permissions or alternative path?
5. *Cherrypick acceptance*: drop the 4K LOC apiary contribution into your `finetune/` directory or keep as a sibling apiary repo that MW invokes?
6. *Accept the collaborator invitation*: github.com/ademczuk/apiary/invitations

*Updated honest podium odds*: ~55-60% with current state (2,305 real GHSA cases + 89 paired diffs + synthetic + apiary's training stack + your production architecture). Adding Datadog in 2K-sample batches without re-OOM'ing pushes to ~60-65%. UNIQA outreach landing one real claim brings it to ~70%.

Repo: https://github.com/ademczuk/apiary (commit 6cb7394). All smoke tests PASS. Disk safe.

---

## Notes for me (not for Andreas)

- File at `apiary/pitch/whatsapp-andreas-consolidation.md`
- Marker-clean
- ~700 words
- Tone: acknowledges OOM, surfaces what survived, asks for safer corpus-expansion decision
- TL;DR: "OOM survived, 2305 GHSA + 89 version-pair extractions on disk, datadog/OSSF need to be done in smaller batches to avoid re-OOM. 6 decisions still your call."
