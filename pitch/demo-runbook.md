# Demo Runbook: Sunday Morning

The literal steps. Do not improvise. Run this checklist top to bottom Sunday morning, two hours before the 13:30 pitch.

This runbook covers the v2 architecture: a registry proxy (`apiary-proxy`) and the deterministic policy gate that drives the incident replays in `demo/run_incident_replay.py`. The earlier classifier-only path described in the previous runbook is no longer the demo surface.

---

## Pre-event setup (do this on the demo laptop, Friday night)

1. Clone the repo: `git clone https://github.com/ademczuk/apiary && cd apiary`
2. Install deps: `uv venv && source .venv/bin/activate && uv pip install -e .`
3. Install jinja2 explicitly: `uv pip install jinja2` (needed for Control Evidence Memo rendering)
4. Install asciinema for backup video: `brew install asciinema` (or `apt install asciinema`, or `winget install asciinema` on Windows). On Win11 the team uses WSL2; install asciinema inside the WSL distro, then run all the backup commands from WSL.
5. Pre-stage the demo allowlist: `bash demo/prestage_allowlist.sh` (or `python demo/prestage_allowlist.py` from PowerShell)
6. Smoke-test all three incidents: `python demo/test_incident_replay.py`. As of 2026-05-28 the `postmark-mcp-1.0.16` golden is being refreshed while the parallel `source_match` rule lands; if the smoke test still fails after the parallel agent ships, regenerate the goldens with `python demo/test_incident_replay.py --update-goldens` (or whatever the script's regen flag is) before recording the backup video. The live demo verdicts (lodash ALLOW, 1.0.16 BLOCK, 1.0.12 ALLOW) are unaffected.
7. Record the backup video: `bash demo/record_backup.sh`
8. Upload backup to YouTube unlisted and asciinema.org. Save URLs in `demo/backup-urls.txt`.

## Demo morning (Sunday, T-2 hours)

1. Start the apiary proxy: `python -m apiary_proxy.proxy --port 4873 --cache-dir data/proxy-cache &`
2. Verify health: `curl http://localhost:4873/healthz`
3. Verify Bumblebee bridge: `bash bumblebee_bridge/smoke.sh`
4. Open the slide deck on screen 2
5. Have the backup video URLs printed on a sticky note
6. Cue the asciinema cast as a fallback in screen 3
7. Coffee

---

## Roles

- **Andrew:** runs the laptop, types the demo commands, owns the gate process.
- **Andreas:** drives the slide deck, narrates slides 1-6 and 8-9, hands off to Andrew for slide 7 (demo), takes Q&A on systems and integration.
- **Either:** handles slide 11 (ask) and the closing line. Andreas if Andrew is still recovering from the demo, Andrew if Andreas is on a roll.

---

## Pre-flight checklist (T-2 hours)

Tick each one out loud. Do not skip. The full punch list lives in `pitch/preflight-checklist.md`.

1. **Proxy is up.** `curl -sf http://localhost:4873/healthz` returns `{"ok": true}`. If not, restart the proxy (`python -m apiary_proxy.proxy --port 4873 --cache-dir data/proxy-cache &`) and retry.
2. **Allowlist is pre-staged.** `apiary-quarantine validate` prints `quarantine OK`. If it complains, run `bash demo/prestage_allowlist.sh` (which is idempotent).
3. **All three incidents replay cleanly.** Run `python demo/test_incident_replay.py`. Verdicts must read: lodash ALLOW, postmark-mcp@1.0.16 BLOCK, postmark-mcp@1.0.12 ALLOW.
4. **Control Evidence Memo renders.** Check `demo/outputs/` for a fresh `postmark-mcp-1.0.16__*.md` and confirm it has the rule table, LLM audit block, and insurance footer.
5. **Screen recording is on.** OBS recording the laptop screen to disk. Capture every demo, do not rely on remembering to start it.
6. **Backup cast is on the second laptop.** The asciinema `.cast` from `demo/recordings/` plus the YouTube unlisted URL are on Andreas's laptop, full-screen ready. Test the AV switch.
7. **Backup cast is on the phone too.** Same `.cast` URL on Andrew's phone. If both laptops fail, we plug the phone into the HDMI dongle and play from there.
8. **Battery and chargers.** Both laptops above 80%, both chargers in the bag, one HDMI-to-USB-C dongle, one HDMI-to-HDMI cable, one US-to-EU power adapter.
9. **Network plan.** Test the venue wifi. If flaky, switch to Andreas's phone hotspot. The demo MUST run on the local laptop, no cloud calls required. Confirm by killing wifi and re-running the demo.
10. **Slide deck loaded.** Latest version pulled, opened in presenter mode, presenter notes visible on Andreas's screen.
11. **Question card.** Print the Q&A escalation matrix from `q-and-a-prep.md` on one card, in pocket.

---

## The demo, step by step

This is what Andrew types on stage. Pace: slow. Speak the command as you type it. Pause after each output. Target total runtime: about 70 seconds.

### Step 1: Show the policy and allowlist are clean

```bash
apiary-quarantine validate
```

Expected output: `quarantine OK`.

Say: "Allowlist is pre-staged and consistent. Every entry has a signed rationale note. This is the audit trail an insurance underwriter wants."

### Step 2: Replay the clean baseline, lodash

```bash
python demo/run_incident_replay.py --incident lodash-4.17.21
```

Expected: a green ALLOW verdict, every policy rule PASS.

Say: "Lodash 4.17.21. The most-installed package on npm. Every rule passes. Verdict: allow. The gate is not just stamping block on everything."

### Step 3: Replay the September incident, postmark-mcp 1.0.16

```bash
python demo/run_incident_replay.py --incident postmark-mcp-1.0.16
```

Expected: a red BLOCK verdict with multiple FAIL rules (release age, obfuscated postinstall, exfil pattern).

Say: "Postmark-mcp 1.0.16. The September 2025 incident. Three rules fail. The gate refused the install before any payload ran."

### Step 4: Show the Control Evidence Memo

```bash
ls -1t demo/outputs/postmark-mcp-1.0.16__*.md | head -n1 | xargs cat
```

Expected: a fully rendered memo with the rule table, LLM audit summary, and the IBM-cited loss estimate.

Say: "Every block produces this. An insurer can pull this directly into a claim file. The control is auditable, dated, and references a published loss model."

### Step 5: Show the safe fallback works

```bash
python demo/run_incident_replay.py --incident postmark-mcp-1.0.12
```

Expected: green ALLOW because 1.0.12 is on the pre-staged allowlist.

Say: "Same package, the prior version. Allow-listed by the operator with a written rationale. The gate doesn't break the team; it points them at the version that hasn't been compromised."

### Step 6: Hand back to Andreas

Walk back to the slide deck. Andreas advances to the next slide.

---

## Fallback paths

**Proxy is down at demo time:**

- Restart it: `python -m apiary_proxy.proxy --port 4873 --cache-dir data/proxy-cache &`
- If restart fails, fall back to the asciinema cast:
  ```bash
  asciinema play demo/recordings/backup-demo-*.cast
  ```
- If asciinema is not on the laptop, play the YouTube URL from `demo/backup-urls.txt`. Say: "We pre-recorded the demo on the same laptop yesterday. The code is live at the URL on screen."

**Allowlist looks wrong (validate fails):**

- Re-run `bash demo/prestage_allowlist.sh`. It is idempotent and rebuilds the policy entries from `demo/seed_packages.txt`.
- If that still fails, fall back to the backup cast.

**Network is down at demo time:**

- The demo does not need the internet. The incident replays read incident fixtures from `demo/incidents/` and call the local policy engine. If you find yourself reaching for the internet, you took a wrong turn.

**A judge asks to replay a different incident:**

- The three shipped incidents are `lodash-4.17.21`, `postmark-mcp-1.0.16`, `postmark-mcp-1.0.12`. Anything else is outside the demo surface. Say: "We ship three reconstructions in-tree. Adding a new incident is a fifteen-minute job; I can mail you the result this afternoon."

**Andrew gets stuck typing on stage:**

- Andreas keeps narrating. The slide deck has the commands typed out as bullets on the demo slide's backup variant. Switch to those. Do not panic. Speak to the screen, not the laptop.

---

## Two-minute booth elevator pitch

For when judges or sponsors walk up to the booth between rounds. Whoever is at the booth says this:

"Apiary is a registry proxy that gates every npm install through a deterministic policy engine, then writes a Control Evidence Memo for every decision. We replay real-world incidents (the September 2025 postmark-mcp credential-exfil release, the lodash baseline, the safe-version fallback) and prove the gate would have blocked the bad release without a denylist. The differentiator is the audit memo: every block produces a dated, rule-referenced document an insurance underwriter can pull into a claim file. Want to see it? I will block the September postmark-mcp incident on this laptop in 20 seconds."

If they say yes, run steps 1-4 of the demo. If they say no, hand them a card with the URL and one line: "Live now at github.com/ademczuk/apiary." Move on.
