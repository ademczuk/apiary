# Apiary Slide Deck

12 slides. Built for a 5-7 minute pitch with 2-3 minutes of Q&A. Markdown for now; convert to Google Slides or Pitch once the visual language is locked.

Speaker rotation: Andrew presents slides 1-4 and 6 (demo). Andreas presents 5, 7, 8, 9, 10. Either takes 12 (ask). Slide 11 only comes out if a judge asks.

The deck is structured around the v2 architecture: a self-hosted npm registry proxy that gates installs against deterministic policy before tarballs reach a developer machine. The CodeBERT classifier from v1 is still in the tree, but it has been demoted to one supplementary signal among several. The story is about the gate, the evidence artifact, and the underwriting math.

---

## Slide 1 - The problem

**Speaker note:** "npm is the largest software registry on the planet, and the most attacked. Three million packages, two hundred thousand new versions every week. In September 2025 a maintainer's account for postmark-mcp got taken over and a credential exfiltration payload shipped to fifteen hundred organizations before anyone noticed. event-stream in 2018, ua-parser-js in 2021, the eslint-scope compromise, the Lottiefiles incident. The pattern is the same: trusted maintainer, one bad version, thousands of installs in the window between push and patch."

**Visual:** Timeline. X-axis: 2018 to 2026. Each named incident as a labeled dot, sized by estimated affected installs. postmark-mcp on the right with a red ring around it.

**Bullets:**
- 3M packages, 200K new versions per week
- postmark-mcp@1.0.16: 1,500 orgs, September 2025
- event-stream, ua-parser-js, eslint-scope: same pattern, different year
- The window between push and patch is the attack surface
- Sonatype: 512K malicious packages logged in 2024, 98.5% concentrated in npm

**Judges' question this answers:** "Why does this problem matter right now?"

---

## Slide 2 - Deterministic policy beats probabilistic scoring

**Speaker note:** "Most existing tools answer 'is this package vulnerable?' after the install. We answer 'should this install happen at all?' before the tarball ships. A score is not a control. Underwriters cannot price a model. They can price a rule that fires deterministically, leaves an audit trail, and never has to explain itself with a confidence interval. So the v2 architecture flipped: the gate is rule-based, the model is one signal among several, and every decision produces evidence."

**Visual:** Side by side. Left: a probability score with shaded uncertainty band. Right: a rule list with PASS / FAIL stamps and a single hard verdict. Arrow from right side to a printed evidence memo.

**Bullets:**
- A score is not a control. A rule is.
- Five deterministic rules, explicit allow / quarantine / block semantics
- Every decision ships with a Control Evidence Memo
- Maps to ISO 27001 A.8.28, NIST SSDF PS.3.1, CIS Control 16
- The model is a signal. The policy is the product.

**Judges' question this answers:** "Why not just use Snyk?"

---

## Slide 3 - Architecture

**Speaker note:** "Four pieces. The registry proxy speaks the npm registry API and sits between the developer and the public registry. The policy engine evaluates five deterministic rules on every tarball serve: release age, lifecycle script triage, SRI checksum verification, source match, quarantine database lookup. The quarantine workflow holds packages for review with mandatory sibling rationale notes, validated by a git pre-commit hook. The LLM audit pipeline runs OpenAI, local Ollama, or a Dwarfstar-compatible endpoint, with a cache seeder that pre-audits the top 2000 packages overnight. Self-hosted, on-premise, no SaaS round trip."

**Visual:** Four boxes left to right with arrows: Developer / CI then Registry Proxy then Policy Engine then Allow or Quarantine or Block. Below: LLM Audit Pipeline feeding into Policy Engine. Above the proxy: a small box labeled "Cache (top 2000 pre-audited)".

**Bullets:**
- Registry proxy (`apiary_proxy/`): speaks npm API, caches tarballs, logs every request
- Policy engine (`apiary_policy/`): 5 rules, allow / quarantine / block
- Quarantine workflow (`apiary_quarantine/`): sibling rationale Markdown, git-validated
- LLM audit (`apiary_auditors/`): OpenAI, Ollama, Dwarfstar backends
- Cache seeder (`apiary_cache/`): pre-audits popular packages so installs hit cache

**Judges' question this answers:** "How does this fit into a developer's workflow?"

---

## Slide 4 - The model: one signal, not the centerpiece

**Speaker note:** "v1 was a CodeBERT classifier. It is still in the tree under `scripts/` and `modulewarden_gate/`, and it remains useful as a probabilistic signal for packages the policy engine has not yet audited. But it is no longer the centerpiece. The reason: a model that scores 0.94 cannot be underwritten. A rule that fired on a specific lifecycle hook can. The model now feeds into the LLM audit pipeline as one input, and the gate decision rides on the deterministic rule set. We will show the trained numbers in the appendix if asked, but the pitch is the gate."

**Visual:** Same architecture diagram as Slide 3, with the CodeBERT model rendered as a small box feeding into the LLM Audit Pipeline. Faded color to signal demoted status. Caption: "v1 classifier, retained as one signal."

**Bullets:**
- CodeBERT + LoRA fine-tune on the figshare benchmark, 210K labeled releases
- Trained on Leonardo, retained in `scripts/train_codebert.py`
- Now feeds the LLM audit pipeline, not the gate decision
- The gate decision is rule-based and auditable
- Honest framing: the model is useful, the policy is the product

**Judges' question this answers:** "What happened to the classifier you talked about earlier?"

---

## Slide 5 - Live demo: postmark-mcp incident replay

**Speaker note:** "This is the gate replaying the September postmark-mcp incident. Faithful reconstruction of version 1.0.16, the one that shipped credential exfiltration. We run it through the deterministic policy. Watch what the gate does, and watch the evidence memo that drops out."

The speaker runs the demo. `python -m demo.run_incident_replay --incident postmark-mcp-1.0.16`. Show the colored rule table. Show the BLOCK verdict. Open the generated Control Evidence Memo in a second pane so the judges can read it. Then run the clean baseline (`postmark-mcp-1.0.12`) and the popular-package baseline (`lodash-4.17.21`) to prove the gate is not just stamping BLOCK on everything. Total demo time: 60 seconds.

**Visual:** The slide IS the terminal split with a memo pane. Project the laptop screen full-screen. Backup slide carries a screenshot of the expected output in case the network fails (the demo itself is fully offline).

**Bullets (only visible on the backup slide):**
- `python -m demo.run_incident_replay --incident postmark-mcp-1.0.16` -> BLOCK
- Memo written to `demo/outputs/postmark-mcp-1.0.16__2026-05-28.md`
- `--incident postmark-mcp-1.0.12` -> ALLOW (last known clean release)
- `--incident lodash-4.17.21` -> ALLOW (popular package baseline)

**Judges' question this answers:** "Show me it actually works."

---

## Slide 6 - The math, one customer

**Speaker note (about 30 seconds):** "Take a real underwriting profile. An 18M EUR Austrian SME, around 80 developers, JavaScript and Python stack. Their cyber premium today sits at 142k a year. The underwriter's expected loss ratio on the account is 41 percent, anchored to NAIC and Munich Re 2024 figures. After Apiary is deployed, every install routes through the gate and every decision ships with a Control Evidence Memo. Apply Coalition's published control-class credit of 12.5 percent, plus the reduction in supply chain exposure that Verizon and Sonatype both pin at the install layer. Year 1 premium drops to 121k. Loss ratio drops to 27 to 30 percent. The customer renews and UNIQA picks up 11 to 14 points of margin on the account."

**Visual layout:**

Two columns separated by a wide arrow pointing right.

| Pre-Apiary (left column) | Post-Apiary (right column) |
|---|---|
| Premium: 142k EUR per year | Premium: 121k EUR per year |
| Expected loss ratio: 41 percent | Expected loss ratio: 27 to 30 percent |
| Supply chain exposure: uncontrolled | Supply chain exposure: gated, attested |
| Evidence on renewal: asserted | Evidence on renewal: queryable |

Bottom strip below the arrow:

**Margin uplift: +11 to +14 percentage points per account**

**Bullets (small, under the visual):**
- 142k baseline anchored to Austrian SME band (Stoik, Finlex)
- 41 percent loss ratio anchored to NAIC 2024 cyber report
- 12.5 percent control-class credit anchored to Coalition MDR program
- 15 percent supply chain breach share anchored to Verizon DBIR 2024

**Judges' question this answers:** "Why would an insurer actually pay you?"

---

## Slide 7 - Why UNIQA wins too

**Speaker note (about 20 seconds):** "Three things change for the carrier. The at-risk account renews instead of churning to a cheaper insurer. Margin on the account goes up by 11 to 14 points on the eligible segment, 2 to 4 points across the full book once you weight for eligibility. And the same control class scales. Every JavaScript-heavy account in the CEE book is addressable with the same memo template, the same evidence schema, and the same actuarial tier. One control class, hundreds of accounts."

**Visual layout:**

Three large bullets, each with an icon and a one-line caption. Stacked vertically, equal weight.

1. **Retention.** Tech-heavy SMEs are the most actively shopped segment in the European cyber market. The control credit is a switching-cost increase.
2. **+11 to +14 pt account margin, +2 to +4 pt book margin.** Per-account math from Slide 6. Book math weighted for eligibility.
3. **Scales across the CEE book.** One control class, one evidence schema, one actuarial tier. Reusable from the first account onward.

**Footer (small text):** "All numbers anchored to NAIC, Coalition, Verizon, Sonatype, Munich Re 2024 reports. See `pitch/underwriter-economics.md` for citations."

**Judges' question this answers:** "Is this a product or a feature?"

---

## Slide 8 - Roadmap

**Speaker note:** "What ships next. The source-match rule is currently a stub; closing that out lets us attest to provenance, not just publisher identity. PyPI is the obvious second ecosystem because the proxy pattern is identical and the figshare-equivalent dataset already exists. Federated learning across customer audit decisions lets us improve the model without anyone shipping us their code. And SOC 2 Type II is the artifact that turns the gate into a billable enterprise control instead of a pilot."

**Visual:** Three columns. Q3 2026: source-match rule, PyPI proxy. Q4 2026: federated audit, RubyGems. 2027: SOC 2 Type II, registry mirror integration.

**Bullets:**
- Source-match rule: closes the v2.0 stub, attests publisher-to-repo provenance
- PyPI: next ecosystem, same proxy architecture, Q3 2026
- Federated audit: customer decisions improve the model, code stays local
- RubyGems: Q4 2026
- SOC 2 Type II: turns the gate into a billable enterprise control

**Judges' question this answers:** "Where does this go after the hackathon?"

---

## Slide 9 - Team

**Speaker note:** "Andrew is the ML lead. Built the v1 classifier, the training pipeline, and ran the Leonardo job. Andreas is the systems engineer. Built the registry proxy, the policy engine, the quarantine workflow, and the audit pipeline. We have been collaborating on supply chain tooling for three years and have shipped together before."

**Visual:** Two photos, name, one-line description. No long CVs.

**Bullets:**
- Andrew Demczuk: ML engineering, classifier, training pipeline
- Andreas Petersson: systems engineering, registry proxy, policy engine, audit pipeline
- Three years of collaboration on supply chain tooling

**Judges' question this answers:** "Can you actually build this past Sunday?"

---

## Slide 10 - What is and is not shipped

**Speaker note:** "Honest scope. The registry proxy, the policy engine, the quarantine workflow, the audit pipeline, and the demo replay all work end to end and are in the repo. Three things we knowingly punted: the source-match rule is a stub that always returns False, so the demo allowlist short-circuits it for the clean baselines; the figshare label fix for one mislabeled benign batch is documented but not applied to the v1 classifier; and the proxy cache uses simple TTL eviction, not LRU. If a judge pokes at the repo we want them to find what we already know is missing."

**Visual:** Two-column table. Left: "Ships in v2.0". Right: "Knowingly deferred". Each side has a bulleted list. No padding or bluffing.

**Bullets (left):**
- Registry proxy with metadata rewrite and tarball serving
- 5-rule policy engine
- Quarantine workflow with sibling rationale validation
- LLM audit pipeline, three backends
- postmark-mcp incident replay with Control Evidence Memo

**Bullets (right):**
- Source-match rule (stub, demo short-circuits with allowlist)
- Figshare label fix for one mislabeled benign batch (v1 classifier only)
- LRU cache eviction (currently TTL only)

**Judges' question this answers:** "What is real and what is hand-waved?"

---

## Slide 11 - Eval methodology (held in reserve)

**Speaker note:** Only show this slide if a judge asks about the model side. "v1 train-validation-test split is 70-15-15 stratified by malicious vs benign. The held-out test set is real malicious packages from the figshare benchmark, never touched during training or hyperparameter selection. The synthetic 50K is in training only. Cross-validation is 5-fold. We can show the per-pattern breakdown to confirm the model is not just memorizing the synthetic distribution. The model now feeds the LLM audit pipeline, not the gate decision, so generalization failure modes degrade gracefully to the deterministic rules."

**Visual:** Data flow diagram. Boxes: raw figshare, synthetic generator, train (50K synth + 70% real), val (15% real), test (15% real). Arrows. Model card style.

**Bullets:**
- Stratified 70-15-15 split on real data
- Synthetic 50K only in train, never in val or test
- 5-fold CV for model selection
- Per-pattern breakdown available
- v2 architecture: model failure degrades to deterministic policy, not silent allow

**Judges' question this answers:** "How do I know your model numbers are not overfit?"

---

## Slide 12 - Ask

**Speaker note:** "Three asks. First, a pilot with a sponsor or one of the underwriters in the room. We supply the gate and the evidence schema. You keep the data and the actuarial conclusions. Second, continued Leonardo or H100 access through the end of June so we can finish the source-match rule and the PyPI proxy. Third, a thirty-minute conversation with UNIQA's cyber product team to validate the control-class framing. The math on Slide 6 is anchored to public industry data, but it gets sharper with one real account profile in front of it."

**Visual:** Three icons with one-line asks underneath. Handshake, GPU, briefcase.

**Bullets:**
- Pilot with a sponsor company. We supply the gate, they keep the data.
- Compute access through June for source-match and PyPI proxy
- 30-minute conversation with UNIQA's cyber product team

**Judges' question this answers:** "What do you want from us?"

---

## Backup material (not slides, in the back of the deck)

- Confusion matrix on a per-pattern basis (v1 classifier)
- Latency benchmark at varying cache hit rates (proxy and gate)
- Comparison table: Apiary vs Verdacccio vs Snyk vs Socket.dev vs npm audit, positioned on the gate / scan / audit axis
- Sample Control Evidence Memo rendered to PDF
- Per-rule audit log JSONL sample
- Cost-of-attack estimate: average cost per malicious install based on IBM Cost of a Data Breach 2024 (USD 4.91M per supply chain compromise, 267-day mean time to identify and contain)
