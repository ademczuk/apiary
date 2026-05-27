# Apiary Demo Preflight Checklist

Single-page punch list. Execute Saturday night, then re-execute the time-sensitive items Sunday morning at T-2 hours. Strike through items aloud as you complete them.

Keep this file open on the second laptop. Tag any FAIL item with a name and a fix-by time.

---

## 1. Repo state

- [ ] `git status` on the demo machine shows clean working tree, no uncommitted edits
- [ ] `git pull --ff-only` succeeds against `origin/main`
- [ ] `git log -1 --oneline` matches the head of the deck's "what's shipped" slide
- [ ] `uv pip install -e .` exits 0 with no warnings about missing extras
- [ ] `uv pip install jinja2` returns "Requirement already satisfied"
- [ ] `pytest -q` returns 0 (or, if known-flaky, ignored tests are documented in the deck)
- [ ] `apiary-quarantine validate` prints `quarantine OK`

## 2. Demo machine

- [ ] Proxy starts cleanly: `python -m apiary_proxy.proxy --port 4873 --cache-dir data/proxy-cache &`
- [ ] `curl -sf http://localhost:4873/healthz` returns `{"ok": true}` (or current expected payload)
- [ ] Allowlist is staged: `bash demo/prestage_allowlist.sh` prints the "Pre-staged N packages" summary
- [ ] All three incidents run: `python demo/test_incident_replay.py` exits 0
- [ ] Fresh Control Evidence Memo exists at `demo/outputs/postmark-mcp-1.0.16__<today>.md`
- [ ] `demo/recordings/backup-demo-*.cast` exists and is under 5 MB
- [ ] Backup cast plays end to end: `asciinema play demo/recordings/backup-demo-*.cast`
- [ ] Terminal font size is set to demo-readable (target row 2 of the venue back wall)
- [ ] System sleep + lid-close power settings are set to "do nothing" for the next 4 hours
- [ ] Display sleep timer is disabled
- [ ] Notifications are silenced (Do Not Disturb / Focus mode on)
- [ ] Slack, Discord, mail clients are quit (not just minimized)

## 3. Slide deck

- [ ] Final version locked on `pitch/slide-deck.md` (no edits after T-2)
- [ ] Deck renders identically on the demo laptop's projector resolution (1920x1080, then 1280x720 fallback)
- [ ] Custom fonts render; no glyph substitution boxes on any slide
- [ ] Speaker notes are visible on the secondary screen only
- [ ] Slide 7 (demo) has the backup-variant bullets visible if Andrew freezes
- [ ] Slide 11 (the ask) has the right contact email and repo URL
- [ ] Page numbers match what Andreas will call out from the script
- [ ] No tracked-changes or comment bubbles visible in the export

## 4. Network

- [ ] Venue wifi credentials saved, tested with `curl https://example.com`
- [ ] Hotspot fallback: Andreas's phone hotspot password is on the sticky note
- [ ] Hotspot tested: laptop joins, can reach example.com
- [ ] Demo runs with wifi OFF (proves the demo is local-only)
- [ ] No background process is making cloud calls during the demo (check `lsof -i` or `netstat -an` for surprises)

## 5. Roles

- [ ] Andrew confirms he runs the laptop and types the demo commands
- [ ] Andreas confirms he drives slides 1-6 and 8-9, takes Q&A on integration
- [ ] Handoff at slide 7 is rehearsed once on Saturday night
- [ ] Q&A backstop named: if asked something neither knows, the answer is "great question, we will follow up by email today"
- [ ] One of the two has the Q&A escalation card from `pitch/q-and-a-prep.md` in pocket

## 6. Submission

- [ ] Final deck uploaded to the submission portal (PDF + source)
- [ ] Repo link in the submission form points to a public commit, not a branch HEAD that can move
- [ ] Demo video (the asciinema-derived YouTube unlisted URL) is in the form
- [ ] `demo/backup-urls.txt` is committed and pushed so the link survives a fresh clone
- [ ] Model card (if the deck mentions one) is uploaded
- [ ] Team contact email is monitored on both phones for judge follow-ups
- [ ] Submission confirmation email is saved to a phone screenshot (proof of timestamp)

## 7. Stage kit (in the bag)

- [ ] Both laptops above 80% battery
- [ ] Both chargers
- [ ] HDMI-to-USB-C dongle
- [ ] HDMI-to-HDMI cable, 2 m or longer
- [ ] US-to-EU power adapter
- [ ] Sticky note with hotspot password and backup video URLs
- [ ] Printed Q&A card
- [ ] Phone with the backup cast URL cached offline
- [ ] Water bottle

---

## Sign-off

- Saturday night execution: ___ (initials) at ___ (time)
- Sunday morning re-check: ___ (initials) at ___ (time)
- Any FAIL items left open: ___ (list with fix-by times)
