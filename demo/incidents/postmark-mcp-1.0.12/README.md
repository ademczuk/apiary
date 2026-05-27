# postmark-mcp@1.0.12 - clean baseline

Pre-compromise release of the postmark-mcp MCP server. Carries no
lifecycle scripts, a valid `repository.url` pointing at the upstream
GitHub mirror, and a `gitHead` pointer for source-match verification.

This directory is the safe fallback the Apiary demo recommends when the
malicious 1.0.16 release is blocked. Expected verdict for the policy
gate: **allow** once the release-age clock is wound back past the
14-day minimum (the demo runner does this with a synthetic publish
timestamp).
