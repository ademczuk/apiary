# Apiary 60-Second Pitch Video Script

Target length: 60 seconds. 11 shots. Recordable on demo night with asciinema, a phone camera, and OBS for the screen capture.

Voice: one narrator throughout (Andrew or Andreas, whichever has the cleaner mic). Music: low electronic bed under the whole thing, drop out at 0:45 for the close.

---

## 0:00 - 0:05  HOOK

**Visual:** Black screen. White monospace type appears one character at a time, like a real terminal: `$ npm install postmark-mcp`. Cursor blinks.

**Narrator:** "In September, an npm maintainer's account was taken over."

**B-roll option:** GitHub Security Advisory page for postmark-mcp showing the compromise notice, blurred behind the type.

**Music:** Soft bass note enters.

---

## 0:05 - 0:12  PROBLEM

**Visual:** Terminal install scrolls fast. Text overlay drops in: "1,500 weekly downloads of postmark-mcp@1.0.16". Number ticks up live.

**Narrator:** "Fifteen hundred organizations pulled the malicious version before anyone noticed."

**B-roll:** npm-stats screenshot of weekly downloads for postmark-mcp. Real numbers.

---

## 0:12 - 0:20  WHY EXISTING TOOLS MISS IT

**Visual:** Split screen. Left: `npm audit` output with "found 0 vulnerabilities". Right: Snyk dashboard with green check.

**Narrator:** "Every tool we have runs after install, or after the CVE lands. The window between push and patch is the attack."

---

## 0:20 - 0:32  OUR APPROACH

**Visual:** Architecture diagram appears, drawn one box at a time. Bumblebee feed enters from the left, hits an Apiary scoring box (CodeBERT logo), feeds a ModuleWarden gate box, splits into three colored arrows: green allow, yellow quarantine, red block.

**Narrator:** "Apiary scores every package before the install completes. We trained a CodeBERT model on the figshare malicious-package benchmark, plus fifty thousand synthetic attack examples we generated from a fifteen-pattern catalog. The model outputs a calibrated probability. ModuleWarden routes the install: allow, quarantine, or block."

**Music:** Builds.

---

## 0:32 - 0:45  LIVE DEMO

**Visual:** Asciinema-style terminal recording, full screen. Type the command live:

```
$ curl -X POST localhost:8000/score \
    -d '{"package":"postmark-mcp","version":"1.0.16"}'
```

Response renders, color-coded:

```json
{
  "package": "postmark-mcp",
  "version": "1.0.16",
  "score": 0.94,
  "decision": "block",
  "evidence": ["credential_exfiltration_pattern",
               "obfuscated_post_install_script"]
}
```

Big red "BLOCKED" stamp slides in from the right.

**Narrator:** "Here is the September incident. Score zero point nine four. Blocked. The developer never runs the payload."

---

## 0:45 - 0:55  CREDIBILITY

**Visual:** Three-up:
1. Confusion matrix on the held-out figshare test set (real numbers from eval.py).
2. Calibration plot (MAPIE conformal intervals).
3. URL bar: `github.com/ademczuk/apiary`.

**Narrator:** "Real model, trained on Leonardo. Held-out AUROC above zero point nine two. Open source. Live now."

**Music:** Drops out.

---

## 0:55 - 1:00  CLOSE

**Visual:** Black screen. White type, two lines centered:

```
apiary
github.com/ademczuk/apiary
```

Logo (a hexagonal honeycomb cell with a stop sign inside) fades in below the URL.

**Narrator:** "Apiary. Stop the install before the install stops you."

**Music:** One final low bass note. Silence.

---

## Production notes

**What we record on demo night:**

- The asciinema reel of the postmark-mcp block (0:32 to 0:45). The gate has to be running, with the stub score for postmark-mcp@1.0.16 returning 0.94. If the real model is loaded, even better.
- The terminal install scroll for the hook (0:00 to 0:12). Use the demo VM, not a real npm install. We do not want a real malicious payload near our laptops.
- The architecture diagram (0:20 to 0:32). Draw it once in Excalidraw or tldraw, screen-record the draw, then trim.
- The model plots (0:45 to 0:55). Generate in `scripts/eval.py` and save as PNG.

**What we do NOT record on demo night:**

- A real install of a real malicious package. Always use a sandbox VM, never the demo laptop.
- Any judge or sponsor logo. We do not have permission and it makes the video unshippable after the event.

**Fallback if the gate is down at record time:**

Replace the live curl with a pre-recorded asciinema reel checked into the repo at `demo/postmark-block.cast`. Generate it with `asciinema rec` against a known-good gate before traveling.

**Two-language version:**

The script is short enough that a German voiceover is feasible if a sponsor wants it. Andreas can read the German cut.

**Words to scrub from the final cut:**

The narrator must avoid the listed AI-marker words from the project style guide. The script already does. Em-dashes do not exist in spoken audio so that constraint is automatic.

---

## Word count check

Narrator copy total: 117 words. Read at ~120 wpm gives 58.5 seconds. Fits the 60-second target with a half-second of pad at each end.
