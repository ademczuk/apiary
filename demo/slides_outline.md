# Slide deck outline

Target: 5 slides. 60 seconds of speaking. One live demo cue.

## 1. The problem
- npm registry: 3M packages, hundreds of new releases per minute.
- Real incidents: event-stream, ua-parser-js, eslint-scope. Each one compromised millions of installs.
- Existing tooling (npm audit, Snyk, GHSA) is reactive: it tells you what was already exploited.

## 2. The pitch
- ModuleWarden: a 3-state gate (allow, quarantine, block) that scores any npm package@version in under 200 ms.
- Trained on 210K labelled releases (figshare NPM Malicious Package Study, CC BY 4.0).
- Pairs with Bumblebee (Apache 2.0, Perplexity) for inventory; we are the verdict layer.

## 3. The model
- CodeBERT LoRA fine-tune (r=16, alpha=32) for sequence-level classification.
- Gradient-booster fallback on hand features (install script, AST shape, string entropy) for CPU-only hosts.
- Conformal calibration via MAPIE: every score ships with a 95 percent interval.

## 4. Live demo
- Pipe 10 npm packages (5 known-malicious, 5 controls) through the gate.
- Table output: package, version, score, decision, source file.
- Expected: 5 blocks, 5 allows, no false positives on the controls.

## 5. Where this goes
- CI hook: pre-install gate that fails the build on a block.
- Editor extension: inline verdict in package.json hover.
- Registry mirror: refuse to serve blocked tarballs to the local cache.

## Backup slide
- Model card: AUROC on held-out test, PR-AUC, calibration plot.
- Honest failure modes: zero-day novel malware, polymorphic install scripts, dependency confusion.
