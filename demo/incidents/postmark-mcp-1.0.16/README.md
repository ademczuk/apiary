# postmark-mcp@1.0.16 - DEMO RECONSTRUCTION

**DO NOT INSTALL. DO NOT EXECUTE. NOT-FOR-EXECUTION.**

## Source incident

In late September 2025, the npm package `postmark-mcp` (a Model Context
Protocol server for the Postmark transactional email service) was
compromised at version 1.0.16. The maintainer pushed a release whose
`postinstall` script monkey-patched the postmark SDK to silently BCC every
outbound email to an attacker-controlled inbox, harvesting transactional
mail (password resets, invoices, internal notifications) from any
downstream user that ran `npm install` between the release date and the
takedown.

Reference: https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/

The legitimate pre-compromise release was version 1.0.12. This directory
ships a sibling `postmark-mcp-1.0.12/` reconstruction so the Apiary
policy gate can be exercised against both the malicious and the clean
release of the same package.

## What this reconstruction contains

- `package.json` - version 1.0.16, references a `postinstall` script
- `postinstall.js` - faithful SHAPE of the malicious code with all
  exfiltration targets replaced by `*.example.invalid` placeholders
- `index.js` - the legitimate-looking MCP server surface that shipped
  alongside the payload in the malicious release

## What this reconstruction does not contain

- working exfiltration code
- a real callback URL
- credential harvesting that actually phones home
- BCC injection that actually patches the postmark SDK

Every "would have" comment in `postinstall.js` documents what the real
malware did. The reconstruction stops at logging the intent to stderr so
a reviewer can read the shape without any network traffic.

## Policy rules that catch this

Run `python demo/run_incident_replay.py --incident postmark-mcp-1.0.16`
to see the deterministic policy decision. Expected verdict: **block**,
with the following rule failures:

1. **release_age** - synthetic publish timestamp is set to today, well
   under the 14-day minimum
2. **install_scripts** - `postinstall` invokes `node postinstall.js`,
   which is a non-trivial command outside the lifecycle allowlist
3. **source_match** - `repository.url` is absent from the package.json,
   so the gate cannot verify the tarball against an upstream commit
