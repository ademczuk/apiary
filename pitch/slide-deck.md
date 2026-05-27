# Apiary Slide Deck

11 slides. Built for a 5-7 minute pitch with 2-3 minutes of Q&A. Markdown for now; convert to Google Slides or Pitch once the visual language is locked.

Speaker rotation: Andrew presents slides 1-4 and 7 (demo). Andreas presents 5, 6, 8, 9. Either takes 11 (ask). Slide 10 only comes out if a judge asks.

---

## Slide 1: The problem

**Speaker note:** "npm is the largest software registry on the planet, and the most attacked. Three million packages, two hundred thousand new versions every week. Last September, a maintainer's account for postmark-mcp was taken over and a credential exfiltration payload shipped to fifteen hundred organizations before anyone noticed. event-stream in 2018, ua-parser-js in 2021, the eslint-scope compromise, the Lottiefiles incident. The pattern is the same: trusted maintainer, one bad version, thousands of installs in the window before the takedown."

**Visual:** Timeline. X-axis: 2018 to 2026. Each named incident as a labeled dot, sized by estimated affected installs. postmark-mcp on the right with a red ring around it.

**Bullets:**
- 3M packages, 200K new versions per week
- postmark-mcp@1.0.16: 1,500 orgs, September 2025
- event-stream, ua-parser-js, eslint-scope: same pattern, different year
- Window between push and patch is the attack surface

**Judges' question this answers:** "Why does this problem matter right now?"

---

## Slide 2: Why probabilistic, not binary

**Speaker note:** "Existing tools are binary. npm audit says vulnerable or not. Snyk says CVE or no CVE. But malicious packages are not boolean. event-stream looked fine until a specific commit. A score with calibrated confidence lets the gate behave like a human reviewer: most things sail through, a few get held for inspection, the obvious ones get stopped. We use conformal prediction to give every score a real confidence interval, not a vibe."

**Visual:** Side by side. Left: a binary classifier with 0 and 1. Right: the same packages on a probability axis, with the quarantine band shaded between 0.05 and 0.30.

**Bullets:**
- Binary tools force a single threshold for everyone
- Calibrated probability lets the gate operate at the right point on the PR curve per team
- Conformal prediction (MAPIE): the 0.94 score ships with [0.91, 0.96] at 95% coverage
- Operators pick risk appetite, not the model

**Judges' question this answers:** "Why is your output more useful than what Snyk already gives me?"

---

## Slide 3: The agent: thresholds, quarantine, human-in-the-loop

**Speaker note:** "The model is one half. The other half is what you do with the score. ModuleWarden is the gate. Below 0.05 the install proceeds. Above 0.30 it is blocked at the resolver, before any code runs. Between those values, the package is quarantined: the install completes into a sandbox directory, the developer gets a notification, and a human approves or rejects. Thresholds are per-customer, hot-reloaded, no restart. The quarantine band is where the false-positive cost lives, and it is the right place for uncertainty to sit."

**Visual:** Decision tree. Score input at top, three branches: allow (green), quarantine (yellow), block (red). Quarantine branch expands into a small UI mock showing "Held for review: postmark-mcp@1.0.16, approve/reject".

**Bullets:**
- Below 0.05: allow
- 0.05 to 0.30: quarantine, human reviews
- 0.30+: block at resolve time
- Thresholds in YAML, hot-reloaded
- Reviewer queue is a Slack message or a CLI prompt

**Judges' question this answers:** "What happens when the model is unsure?"

---

## Slide 4: Architecture

**Speaker note:** "Four pieces. Bumblebee, which is Perplexity's open-source inventory agent, scans the developer's machine or CI and emits one JSON line per installed package. Our bridge consumes that stream and hands each record to Apiary, the scoring service. Apiary runs the CodeBERT model and emits a score plus evidence. ModuleWarden is the gate that maps score to action. The whole loop fits in two hundred milliseconds for cached packages, three to eight seconds for a first-time package that needs feature extraction."

**Visual:** Four boxes left to right, arrows between. Bumblebee, Bridge, Apiary, ModuleWarden. Above each arrow: the data on the wire (NDJSON, scoring request, JSON verdict, decision).

**Bullets:**
- Bumblebee: inventory feed, Apache 2.0
- Bridge: NDJSON consumer, calls scoring API
- Apiary: CodeBERT + LoRA + fallback gradient booster
- ModuleWarden: FastAPI gate, thresholds.yaml drives policy
- Cached scoring: under 100ms. Cold scoring: 3-8s.

**Judges' question this answers:** "How does this actually fit into a developer's workflow?"

---

## Slide 5: The model: CodeBERT plus synthetic data augmentation

**Speaker note:** "The differentiator is the data. The figshare benchmark gives us 6,400 malicious and 7,300 benign packages. That is not enough. So we built a 15-pattern attack catalog from public security taxonomies, post-install droppers, credential exfiltration, dependency confusion, install script obfuscation, typosquats, the rest, and generated 50,000 synthetic malicious examples that vary across the patterns. CodeBERT base, LoRA adapter at r equals 16, fine-tuned on Leonardo. The synthetic data covers attack patterns the real benchmark is sparse on. A held-out test set of real malicious packages, never seen during training, gives us the headline AUROC."

**Visual:** Stacked bar showing training data: 6.4K real malicious, 7.3K real benign, 50K synthetic malicious. Underneath: a small box diagram of CodeBERT plus a LoRA adapter, with the LoRA box highlighted.

**Bullets:**
- Base: figshare NPM Malicious Package Study, 13.7K labeled releases
- Augmentation: 50K synthetic from 15-pattern catalog
- Model: CodeBERT-base + LoRA (r=16, alpha=32)
- Fallback: XGBoost on hand features (CPU only, sub-50ms)
- Hold-out: real malicious test set never seen by the model

**Judges' question this answers:** "What is the technical novelty here?"

---

## Slide 6: The numbers

**Speaker note:** "Target metrics. AUROC at or above 0.92 on the held-out test set. Precision above 0.85 at the 0.30 block threshold. Calibration curve close to the diagonal. We will show the actual numbers from the Leonardo training run, which finishes Saturday night. If the numbers come in below target we will show them anyway and explain the gap. Honest numbers beat aspirational numbers in front of a judging panel that includes a PhD in probabilistic forecasting."

**Visual:** Three plots. ROC curve with AUROC labeled. Calibration plot (predicted probability vs observed frequency, with the diagonal). Precision-recall curve with the operating points (0.05 allow threshold, 0.30 block threshold) marked.

**Bullets:**
- AUROC target: 0.92+ on held-out real malicious
- Precision target: 0.85+ at block threshold
- Calibration: MAPIE 95% intervals, expected coverage validated
- Live numbers shown here, no slide trickery

**Judges' question this answers:** "How well does it actually work?"

---

## Slide 7: Live demo

**Speaker note:** "This is the gate scoring the postmark-mcp incident in real time. The package version 1.0.16 was pulled by 1,500 organizations in September. Watch the score."

The speaker runs the demo. Curl the gate. Show the response. Show the BLOCK decision. Show one allow on a benign control (lodash@4.17.21) to prove the gate is not just stamping BLOCK on everything. Total demo time: 45 seconds.

**Visual:** The slide IS the terminal. Project the laptop screen full-screen. The slide deck has one backup screenshot of the expected output in case the network fails.

**Bullets (only visible on the backup slide):**
- curl POST /score with postmark-mcp@1.0.16
- Response: score 0.94, decision block, evidence list
- curl POST /score with lodash@4.17.21
- Response: score 0.02, decision allow

**Judges' question this answers:** "Show me it actually works."

---

## Slide 8: Roadmap

**Speaker note:** "What ships next. PyPI is the obvious second ecosystem, same architecture, retrain on the public Python malicious package datasets. RubyGems after that. Federated training is the interesting one: every customer's gate sees real installs, including new attacks, but the training data never leaves the customer's network. We push only gradient updates back. That solves the cold-start problem for net new attack patterns without anyone shipping us code."

**Visual:** Three columns. Q3 2026: PyPI. Q4 2026: RubyGems and federated training pilot. 2027: deep registry mirror integration.

**Bullets:**
- PyPI: next ecosystem, same pipeline, Q3 2026
- RubyGems: Q4 2026
- Federated training: gradient updates from customer gates, code stays local
- Editor integration: VSCode and JetBrains, package.json hover with verdict
- Registry mirror: refuse to serve blocked tarballs to the local cache

**Judges' question this answers:** "Where does this go after the hackathon?"

---

## Slide 9: Team

**Speaker note:** "Andrew is the ML lead. Built the model and the training pipeline, ran the Leonardo job. Andreas is the systems engineer. Built ModuleWarden, the FastAPI gate, the threshold engine, and the developer integration. We have been collaborating on supply chain tooling for three years and have shipped together before."

**Visual:** Two photos, name, one-line description. No long CVs.

**Bullets:**
- Andrew Demczuk: ML engineering, training pipeline, model
- Andreas Petersson: systems engineering, gate, integration
- Three years of collaboration on supply chain tooling

**Judges' question this answers:** "Can you actually build this past Sunday?"

---

## Slide 10: Eval methodology (held in reserve)

**Speaker note:** Only show this slide if a judge asks. "Train-validation-test split is 70-15-15 stratified by malicious vs benign. The held-out test set is real malicious packages from the figshare benchmark, never touched during training or hyperparameter selection. The synthetic 50K is in training only, never in test. Cross-validation is 5-fold. Conformal calibration uses split conformal with the validation set. We can show the per-pattern breakdown to confirm the model is not just memorizing the synthetic distribution."

**Visual:** Data flow diagram. Boxes: raw figshare, synthetic generator, train (50K synth + 70% real), val (15% real), test (15% real). Arrows. Model card style.

**Bullets:**
- Stratified 70-15-15 split on real data
- Synthetic 50K only in train, never in val or test
- 5-fold CV for model selection
- Split conformal calibration on val
- Per-pattern breakdown available

**Judges' question this answers:** "How do I know your numbers are not overfit?"

---

## Slide 11: Ask

**Speaker note:** "Three asks. First, a pilot with one of the sponsor companies. We are looking for a real install pipeline to put the gate in front of, with the customer keeping all data. Second, continued Leonardo or H100 access through the end of June so we can finish the PyPI training run. Third, introductions to the cyber-insurance underwriters in the room: the calibrated probability output is the kind of signal that drops directly into actuarial models, and that is a market we have not started selling into."

**Visual:** Three icons with one-line asks underneath. Handshake, GPU, briefcase.

**Bullets:**
- Pilot with a sponsor company. We supply the gate, they keep the data.
- Compute access through June for PyPI
- Intro to cyber-insurance underwriters

**Judges' question this answers:** "What do you want from us?"

---

## Backup material (not slides, in the back of the deck)

- Confusion matrix on a per-pattern basis
- Latency benchmark at varying cache hit rates
- Comparison table: Apiary vs Snyk vs Socket.dev vs npm audit, positioned on capability axes
- Cost-of-attack estimate: average cost per malicious install based on public incident reports
