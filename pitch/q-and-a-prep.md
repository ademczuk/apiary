# Q&A Preparation: Apiary

20 likely judge questions, with answers prepared to roughly 90 seconds of speaking each. Read these before the pitch. The escalation matrix at the bottom covers the questions we cannot bluff.

Rule: honest answers beat aspirational answers. The judging panel includes a PhD in probabilistic forecasting and a 25-year materials COO. They will both spot weak reasoning.

---

## Q1. Is the model better than Snyk's existing tools?

No. Snyk and Socket.dev are excellent at what they do: post-install scanning, dependency graph analysis, CVE correlation. We do something different. Snyk answers "is there a known CVE in this dependency tree?" after the install. We answer "should this install happen at all?" before the install completes. We sit at a different point in the pipeline. Apiary and Snyk stack. A team running both gets the pre-install gate from us and the post-install audit from Snyk. The pitch is not displacement, it is composition.

---

## Q2. What is your false positive rate?

At the 0.30 block threshold, our target precision is 0.85, which is a 15% false positive rate among scored blocks. That is too high to block silently. The quarantine band exists to absorb that uncertainty: anything between 0.05 and 0.30 routes to a human reviewer instead of failing the build. The expected proportion of installs that hit quarantine is low single digits based on the validation set, because the score distribution is bimodal. Most packages cluster near zero. The reviewer queue is therefore tractable. We will show the exact numbers on slide 6 once Saturday training finishes.

---

## Q3. What if the LLM-based audit is wrong?

The LLM is not the only signal. The CodeBERT model is one input. The fallback gradient booster on hand-extracted features (install script presence, AST depth, string entropy) runs in parallel and votes independently. Either can fail the policy. The thresholds layer combines both with explicit weights. If both are uncertain, the package routes to quarantine, not block. The LLM never has unilateral block authority. A wrong LLM verdict on its own gets the package quarantined, not killed.

---

## Q4. How does this work for packages not in your training distribution?

Honestly: novel attack generalization is the hardest open problem in this space, and we do not claim to solve it. Two mitigations. First, the gradient booster on hand features does not need the model to have seen the attack pattern; it triggers on structural signals like a post-install script that downloads and pipes to sh, which is suspicious regardless of payload. Second, the quarantine band catches packages where the model is uncertain. So a net-new attack pattern is more likely to get quarantined than to slip through as an allow. We accept that some net-new attacks will slip through as allows, and that is why we ship telemetry: every block, quarantine, and allow is logged, and customers feed back into a retraining queue.

---

## Q5. Why these thresholds, 0.05 and 0.30?

Calibrated to the validation set. At p equal 0.30, the empirical false positive rate on the validation data is in the target band for our precision goal. At p below 0.05, the empirical true negative rate is above 99%. The 0.05 to 0.30 band is the region where the model's calibration is uncertain enough that we do not want to act unilaterally. These are defaults. Every customer can tune them. A bank might run at 0.02 allow and 0.10 block, accepting more quarantine load. A startup might run at 0.10 and 0.50, accepting more risk for lower friction.

---

## Q6. What is the latency at install time?

Two paths. Cached: under 100 milliseconds. The gate stores verdicts per package version with a configurable TTL. Most installs hit a cached verdict because the package versions a team uses are a small slow-moving set. First-time path: 3 to 8 seconds for a new package version. That covers tarball fetch from the npm registry, feature extraction, model inference. We can show the latency benchmark on the backup slide. A 5-second hit on a first-time install is acceptable; an 8-second hit every install would not be.

---

## Q7. What stops attackers from gaming your model?

Three layers. First, the per-customer rubric does not ship in the model weights. Each customer can configure threshold values, evidence weighting, and required signals. An attacker who learns to score 0.29 on the default model has not learned how to score 0.29 on every customer's gate. Second, the model only outputs a score; the decision policy is downstream and out of band. Third, training data is updated continuously from telemetry, so the model can shift faster than an attacker can probe-and-train. The hardest version of this question is adversarial machine learning research and we do not have a complete answer; the layered design buys us time.

---

## Q8. Is this real or vaporware?

It is real. The public repo is github.com/ademczuk/apiary, the marketing site is live at ademczuk.github.io/modulewarden-website/, and the gate is running at our booth on a laptop you can curl from your phone. Today the score for packages outside the demo seed list is a stub returning 0.02, because Leonardo training finishes Saturday. By Sunday morning the real model is loaded. Either way, the gate, the threshold logic, the bridge, and the Bumblebee integration are running end to end.

---

## Q9. Why npm and not PyPI?

Three reasons. First, attack volume: npm has by far the highest count of malicious packages per year in the public datasets, because JavaScript is in every web pipeline and the install script primitive is broader than pip's. Second, the figshare benchmark we trained on is npm. Third, postmark-mcp is a 2025 incident that everyone in security has seen, and that gives us the demo. PyPI is the next ecosystem and is on the Q3 roadmap. We picked one and shipped, instead of starting both and finishing neither.

---

## Q10. What is your business model?

Three tiers. Free OSS tier: full gate, single threshold profile, community model only. Team tier: 12 per developer per month, custom thresholds, private rubric, reviewer queue with Slack integration. Enterprise: federated training, SLA, single tenant, on-premise option. We are also exploring a cyber-insurance underwriting product where the calibrated probability output feeds into the actuarial model: that is closer to a data sale than a SaaS license.

---

## Q11. How does this fit the sponsor track you are pitching?

(See `pitch/track-reframes.md` for the full per-track answers. The short version for each.)

For UNIQA: software supply chain risk is becoming a cyber-insurance underwriting input, and our calibrated probability output drops directly into actuarial models. We are a data source for an insurance product, not a competitor.

For Infineon: industrial OT systems run firmware that pulls from package registries, including npm via Electron-based HMIs. The same install gate concept applies to firmware update pipelines. The model is the transferable piece.

For Sybilion: harder fit. The closest analog is probabilistic forecasting of supplier risk for industrial procurement. If asked we frame Apiary as a worked example of calibrated probabilistic classification in a high-stakes operational decision, and offer to apply the same methodology to their domain.

---

## Q12. What is your synthetic data strategy and why is it not overfitting?

The 50K synthetic examples are generated from a 15-pattern attack catalog drawn from public security taxonomies: OSSF malicious package categories, CWE entries for supply chain attacks, and the academic literature on npm-specific patterns. Each pattern parameterizes a small grammar that generates code variants. The synthetic data is only in training, never in validation or test. The held-out test set is real malicious packages from the figshare benchmark that the model has never seen. We measure per-pattern accuracy on the test set: if the model only scored well on patterns that were over-represented in the synthetic data, the per-pattern breakdown would show it. We can show that breakdown on slide 10.

---

## Q13. Why CodeBERT and not a larger model like CodeLlama or GPT-4?

Three reasons. First, latency: CodeBERT-base is 125M parameters and runs in under 100ms on a CPU after quantization. A larger model would not fit the under-200ms gate budget. Second, fine-tunability: LoRA on CodeBERT is well understood, runs on a single A100, and produces a model we can ship and version. Third, cost: a per-install GPT-4 call would put the cost-per-install at multiple cents, which is incompatible with a 12-per-developer pricing model. CodeBERT plus LoRA is the right tool for the job. We considered CodeLlama; if the AUROC ceiling on CodeBERT proves too low, the model swap is straightforward.

---

## Q14. What data did you not use, and why?

We did not use Backstabbers Knife Collection because access requires emailing the maintainers from an institutional account, which was outside our 36-hour budget. We did not use private corpus from any vendor because we cannot redistribute the trained model if we do. We did not use raw GitHub issue text because the signal-to-noise is too low for the time we had. We are aware these are gaps. The figshare benchmark plus the synthetic catalog gets us above the AUROC bar; the additional corpora are roadmap items for Q3.

---

## Q15. How does the gate behave when the model service is down?

Two failure modes. First, gate up but model down: the gate falls back to the gradient booster on hand features, which has lower accuracy but does not depend on the CodeBERT service. Second, gate down: the bridge surfaces an error to the developer and the install is held. There is no silent allow on infrastructure failure. We considered fail-open and explicitly rejected it; a security gate that fails open is not a security gate.

---

## Q16. What about transitive dependencies?

The gate scores every package in the resolved tree, not just the top-level dependency. The Bumblebee feed already enumerates transitive dependencies. So if the top-level package is benign but pulls a malicious transitive, the malicious one gets scored and blocked. This is one of the practical advantages of sitting at the install layer instead of at the developer's `package.json`: we see the full resolved graph.

---

## Q17. How long until a customer can deploy this in production?

The free OSS tier is deployable today: clone the repo, start the gate, point Bumblebee at it. Production deployment for a team needs three things: the trained model published as a versioned artifact (Sunday), a Docker container for the gate (Sunday), and a basic Slack-or-CLI reviewer queue for the quarantine band (one week after the hackathon). So a pilot is two weeks out. A fully supported enterprise deployment with SLA is two months.

---

## Q18. What is the worst false positive in your test set, and what did you do about it?

Honest answer: we will know Sunday morning after the held-out evaluation runs. Our prior from the training run is that the worst false positives will be packages with legitimate post-install scripts that look like droppers, things like binary native modules that download platform-specific binaries. The mitigation is the gradient booster, which has explicit features for whitelisted hosts and signed binaries, and the quarantine band, which holds these for review rather than blocking them. We will name the actual worst false positive in the Q&A if asked, after we have the eval output in hand.

---

## Q19. Is there a privacy issue with scoring developer installs?

The scoring request contains the package name and version, nothing else. No customer code is sent to our service. The model runs on the score request alone, plus the tarball fetched from the public npm registry. In the self-hosted deployment (enterprise tier), the model runs entirely in the customer network, so no scoring requests cross the boundary either. We designed for the privacy-strict case from the start because cyber-insurance and financial customers will not adopt a service that ships their dependency manifest to a third party.

---

## Q20. What is your single biggest risk?

The model not generalizing to net-new attack patterns. Every malicious-package classifier in production today underperforms on attack patterns that did not exist in the training data, and there is no known fix for that beyond fast retraining loops. We mitigate with the feature-based gradient booster (structural signals do not require pattern memorization) and the quarantine band (uncertainty routes to humans), but we do not claim to have solved it. The honest framing: we will catch the attacks that look like prior attacks, which is most of them, and we will surface the suspicious ones for human review, which is the right behavior for the rest.

---

## Q&A escalation matrix

When a judge asks something we cannot answer cleanly, do not bluff. The pre-approved escalation phrases:

| Question type | Response template |
|---|---|
| Specific hyperparameter we did not log | "We didn't log that during the 36-hour training window. The artifacts are public, happy to follow up with the exact number by Monday." |
| Specific number we don't have yet | "Saturday training finishes at 2 AM Vienna time. I'll have that for you in the demo Sunday morning, or by email if you want to send a card over." |
| Comparison to a tool we haven't benchmarked | "We have not run a head-to-head against [tool]. Our position is composition, not displacement, so the comparison is about coverage gaps, not accuracy parity." |
| Deep ML research question on which we are not domain experts | "That is an open research question. Our pragmatic choice was [X]; we know it is not optimal and the next iteration would [Y]." |
| Anything we are not sure about | "I'd be guessing if I answered that. Can you say more about what you are trying to determine? I might be able to point you at the relevant artifact." |

The two failure modes to avoid: confident wrong answers, and waffling non-answers. The escalation template gives a clean exit from both.

## Things a judge might bring that we should anticipate

- A laptop. They might want to curl the gate themselves. Have the URL on a card. Have a wifi hotspot if the venue wifi is bad.
- A specific package they know is malicious or sensitive. We can score it live if the gate is running. If it is outside the demo seed list, the stub returns 0.02. Be ready to say "this is a stub today, real model loads Sunday morning" without flinching.
- A specific package they know is legitimate but unusual (a niche internal-looking package, or their employer's npm scope). If we score it as benign, that is a good outcome. If we score it as quarantine, lean into the design: "this is exactly the case where a human reviewer adds value."
