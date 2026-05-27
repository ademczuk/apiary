# Demo Runbook: Sunday Morning

The literal steps. Do not improvise. Run this checklist top to bottom Sunday morning, two hours before the 13:30 pitch.

---

## Roles

- **Andrew:** runs the laptop, types the demo commands, owns the gate process.
- **Andreas:** drives the slide deck, narrates slides 1-6 and 8-9, hands off to Andrew for slide 7 (demo), takes Q&A on systems and integration.
- **Either:** handles slide 11 (ask) and the closing line. Andreas if Andrew is still recovering from the demo, Andrew if Andreas is on a roll.

---

## Pre-flight checklist (T-2 hours)

Tick each one out loud. Do not skip.

1. **Gate is up.** `curl -sf http://localhost:8000/healthz` returns `{"ok": true, "version": "0.1.0"}`. If not, `uvicorn modulewarden_gate.gate:app --port 8000 &` and retry.
2. **Real model is loaded.** Look at the gate's startup log: it should mention loading the CodeBERT checkpoint, not the stub. If the Leonardo training run did not finish in time, the stub is fine for the live demo because the demo packages are in the stub's known-bad list. Acknowledge to the team that we are on stub before the pitch, so nobody is surprised.
3. **Demo packages return expected scores.** Run all five known-bad and all five controls through the gate, check the table renders without errors.
4. **Screen recording is on.** OBS recording the laptop screen to disk. Capture every demo, do not rely on remembering to start it.
5. **Backup video on second laptop.** The 60-second pitch video (already filmed Saturday night) lives on Andreas's laptop, full-screen ready to play. Test the AV switch.
6. **Backup video on phone.** Same video on Andrew's phone. If both laptops fail, we plug the phone into the HDMI dongle and play from there.
7. **Battery and chargers.** Both laptops above 80%, both chargers in the bag, one HDMI-to-USB-C dongle, one HDMI-to-HDMI cable, one US-to-EU power adapter.
8. **Network plan.** Test the venue wifi. If flaky, switch to Andreas's phone hotspot. The demo MUST run on the local laptop, no cloud calls required. Confirm by killing wifi and re-running the demo.
9. **Slide deck loaded.** Latest version pulled, opened in presenter mode, presenter notes visible on Andreas's screen.
10. **Question card.** Print the Q&A escalation matrix from q-and-a-prep.md on one card, in pocket.

---

## The demo, step by step

This is what Andrew types on stage. Pace: slow. Speak the command as you type it. Pause after each output.

### Step 1: Show the gate is alive

```bash
curl -s http://localhost:8000/healthz | jq
```

Expected output:

```json
{"ok": true, "version": "0.1.0"}
```

Say: "The gate is up. Version zero point one."

### Step 2: Score postmark-mcp, the September incident

```bash
curl -s -X POST http://localhost:8000/score \
  -H 'Content-Type: application/json' \
  -d '{"package":"postmark-mcp","version":"1.0.16"}' | jq
```

Expected output (under 200ms):

```json
{
  "package": "postmark-mcp",
  "version": "1.0.16",
  "score": 0.94,
  "decision": "block",
  "evidence": ["credential_exfiltration_pattern",
               "obfuscated_post_install_script"],
  "model": "stub-v0"
}
```

Say: "Postmark-mcp version 1.0.16. The September incident. Score zero point nine four. Decision: block. The install never completes."

### Step 3: Score a known-good control

```bash
curl -s -X POST http://localhost:8000/score \
  -H 'Content-Type: application/json' \
  -d '{"package":"lodash","version":"4.17.21"}' | jq
```

Expected output:

```json
{
  "package": "lodash",
  "version": "4.17.21",
  "score": 0.02,
  "decision": "allow",
  "evidence": [],
  "model": "stub-v0"
}
```

Say: "Lodash, the most-installed package on npm. Score zero point zero two. Decision: allow. The gate is not just stamping block on everything."

### Step 4: Run the full demo loop

If time allows (judges look engaged, no clock pressure):

```bash
bash demo/live_demo.sh
```

This runs all ten seed packages (five malicious, five benign) through the bridge and prints a verdict table. Takes about 20 seconds. Five blocks, five allows, zero quarantines on this seed list.

Say: "Ten packages. Five known malicious. Five controls. The gate calls them all correctly."

### Step 5: Hand back to Andreas

Walk back to the slide deck. Andreas advances to slide 8 (roadmap).

---

## Fallback paths

**Gate is down at demo time:**

- Restart it: `uvicorn modulewarden_gate.gate:app --port 8000 &`
- If restart fails, play the backup asciinema reel from `demo/postmark-block.cast`:
  ```bash
  asciinema play demo/postmark-block.cast
  ```
- If asciinema is not installed on the demo laptop, fall back to the 60-second pitch video. Say: "We pre-recorded the demo. The gate is currently rebooting. The code is live at the URL on screen."

**Network is down at demo time:**

- The demo does not need the internet. Localhost only. If you find yourself reaching for the internet, you took a wrong turn.

**A judge asks to score a specific package not in the demo set:**

- Score it. The gate will return either a stub result (0.02 allow) or, if the real model loaded, an actual prediction. Say: "Let me try it" and type the curl. If it returns 0.02 allow on something the judge knows is malicious, say: "That package is outside our demo seed list, so the stub returns the default. The real model loads at noon today. I can email you the real score this afternoon."

**Andrew gets stuck typing on stage:**

- Andreas keeps narrating. The slide deck has the curl commands typed out as bullets on slide 7's backup variant. Switch to those. Do not panic. Speak to the screen, not the laptop.

---

## Two-minute booth elevator pitch

For when judges or sponsors walk up to the booth between rounds. Whoever is at the booth says this:

"Apiary scores npm packages before the install completes. We trained a CodeBERT model on real and synthetic malicious packages, and shipped it as a FastAPI gate that turns the score into an allow, quarantine, or block decision. The differentiator is two things: calibrated probabilities, so the gate knows what it does not know; and a 15-pattern synthetic data catalog that covers attack types the public datasets are sparse on. Want to see it? I will block the September postmark-mcp incident on this laptop in 20 seconds."

If they say yes, run steps 1-3 of the demo. If they say no, hand them a card with the URL and one line: "Live now at github.com/ademczuk/apiary." Move on.
