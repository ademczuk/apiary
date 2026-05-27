# Track Reframes: Apiary for Infineon, UNIQA, Sybilion

Each track gets one page. The core pitch does not change. What changes is the framing on slides 1, 8, and 11, and the buzzwords we drop into slides 3 and 4. Pick the right reframe at Case Reveal Friday night.

Prior on track fit, in descending order: UNIQA, Infineon, Sybilion. Reasoning at the bottom.

---

## UNIQA Insurance ("AI in Insurance")

**One-line value prop:** "Apiary produces calibrated probabilistic risk scores for software dependencies. That is exactly the signal a cyber-insurance underwriter needs to price a policy."

**Sponsor-domain buzzwords to drop in:**
- "Actuarial" (use it when describing the score: "actuarial probability of a malicious payload")
- "Underwriting input" (frame Apiary as a data feed, not a competing product)
- "Cyber risk quantification" (the term of art UNIQA's cyber product team uses)

**Likely judge profile:** A UNIQA actuary or cyber product lead. They care about: methodological rigor (calibration plot must look right), explainability (every score ships with an evidence list), regulatory framing (Solvency II treats unquantified risk poorly). They do not care about ML novelty.

**Slide swaps:**
- Slide 1 add: "The cyber-insurance market is the fastest-growing P&C segment in Europe. Premium volume tripled 2019 to 2024. Underwriters are starved for signal."
- Slide 6 emphasize: the calibration plot. Lead with it instead of the AUROC. Underwriters trust calibration more than discrimination.
- Slide 8 rewrite: top roadmap item becomes "underwriting data feed for cyber-insurance carriers." PyPI moves to row two.
- Slide 11 rewrite: ask becomes "pilot with UNIQA's cyber product team: we supply the scored dependency telemetry, you build the policy pricing model."

**Track-specific risks:**
- A pure underwriter judge may push hard on regulatory compliance (Solvency II, EIOPA guidelines on model risk management). The honest answer: we are at hackathon stage and a production underwriting input would need full SR 11-7 style model validation. We can credibly position as a research collaboration that feeds into a future production system.
- "Why npm and not the whole IT estate?" is a real question. Answer: we picked a tractable scope to prove the methodology. The methodology generalizes to any quantifiable risk signal a carrier wants to underwrite against.

---

## Infineon Industry ("AI in Industry")

**One-line value prop:** "Industrial OT and embedded systems pull software from package registries too. Apiary is the install gate for the OT software supply chain, where a compromised dependency takes down a fab line, not a web app."

**Sponsor-domain buzzwords to drop in:**
- "OT security" (operational technology, the industry shorthand for industrial control systems)
- "Software bill of materials" (SBOM, mandated by NIS2 and the EU Cyber Resilience Act)
- "Fab line uptime" (Infineon-specific, frame the cost of a supply chain compromise in terms of downtime)

**Likely judge profile:** An Infineon engineering lead or a security architect for industrial customers. They care about: deterministic behavior under failure, fitness for OT environments (latency, air-gap compatibility), CE/EU regulatory alignment (NIS2, CRA). They are skeptical of consumer-grade tooling repackaged for industrial use.

**Slide swaps:**
- Slide 1 add: "EU Cyber Resilience Act requires SBOM and vulnerability tracking for all networked industrial equipment by 2027. The OT software supply chain has fewer tools than the IT supply chain has, not more."
- Slide 4 emphasize: the fallback gradient booster runs CPU-only and works air-gapped. That matters in OT environments where the gate cannot phone home.
- Slide 8 add: "Embedded firmware update pipelines as the third ecosystem after PyPI. Same architecture, smaller language models."
- Slide 11 rewrite: ask becomes "pilot in an Infineon OT line: we deploy the gate in front of an embedded update pipeline, you measure caught-vs-missed."

**Track-specific risks:**
- "How does this run in an air-gapped environment?" is a hard real question. Answer: the gradient booster runs fully offline. The CodeBERT model can ship as a fixed weights file with periodic manual updates. The threshold engine never needs to phone home. We have not tested this end to end and would not pretend otherwise.
- "Are you ISO 27001 certified?" is asked early in any industrial pitch. Answer: no, hackathon stage; a real OT deployment would need a full certification path. We can credibly say the architectural choices (no telemetry by default, deterministic decisions, local-first) align with the industrial requirements.

---

## Sybilion Forecasting ("AI in Forecasting")

**One-line value prop:** "Apiary is a worked example of calibrated probabilistic classification in a high-stakes operational decision. The same methodology, conformal prediction over fine-tuned transformers, applies to industrial procurement risk forecasting."

**Sponsor-domain buzzwords to drop in:**
- "Conformal prediction" (Jonas Falkner's PhD methodology, drop it early and often)
- "Probabilistic forecasting" (the literal track name)
- "Operational decision-making under uncertainty" (the academic framing of the procurement problem)

**Likely judge profile:** Jonas Falkner (Sybilion CTO, PhD in probabilistic forecasting, cares about methodology rigor and proper uncertainty quantification) and Friedrich Weninger (25-year materials industry COO, cares about commercial credibility and whether the tool actually helps a procurement officer make a decision). Two very different judges to satisfy.

**Slide swaps:**
- Slide 1 rewrite: this is the hardest. Frame npm supply chain attacks as a forecasting problem: "given a candidate dependency, forecast the probability that adopting it will result in a security incident within 12 months." That is genuinely a forecasting question and connects to Sybilion's domain language.
- Slide 2 emphasize: conformal prediction. This is the slide that wins or loses Jonas. Show the math: split conformal calibration, marginal coverage guarantee, validity under exchangeability. Acknowledge the limitation that exchangeability breaks under distribution shift.
- Slide 6 lead with: the calibration plot and the per-pattern breakdown. AUROC second.
- Slide 11 rewrite: ask becomes "research collaboration on conformal methods for time-series supply-chain risk forecasting. Our model is a tractable instance; your industrial domain is the harder version."

**Track-specific risks:**
- The biggest risk is that Sybilion judges see npm-security as off-topic for industrial procurement. The reframe above is honest but stretched. If a judge presses on relevance, the right move is to concede the gap and pivot to methodology transfer: "the model is npm. The methodology is general. Here is the formal mapping."
- Jonas will probe the calibration claim hard. He will ask about coverage validity, distribution shift, exchangeability. The escalation matrix in q-and-a-prep.md row 4 covers this: concede the open question, point at the mitigation, do not bluff.
- Friedrich will ask the commercial question. The right answer is to drop into the UNIQA reframe: cyber-insurance underwriting is a real adjacent market with real budget, and the bridge from the demo to that market is clear.

---

## How to pick the track Friday night

After Case Reveal at 6 PM Friday:

1. Read all three briefs. Score each on three axes: domain fit, judge fit, demo fit.
2. Domain fit: how far is the reframe stretch? UNIQA is short, Infineon is medium, Sybilion is long.
3. Judge fit: which judges are in the room for each track, and how well does our pitch land for them?
4. Demo fit: does the live postmark-mcp demo translate? UNIQA yes (cyber risk is the demo). Infineon yes if we cast it as OT supply chain. Sybilion only metaphorically.
5. If two tracks tie on the above, pick the one with the smallest prize spread. €2K vs €1K is much closer than €0 vs €500.

Default pick if briefs do not change the picture: UNIQA Insurance, Infineon as fallback, Sybilion only if the briefs explicitly mention software risk forecasting (unlikely).
