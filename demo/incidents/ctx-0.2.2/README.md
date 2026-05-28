# ctx@0.2.2 - DEMO RECONSTRUCTION (PyPI)

**DO NOT INSTALL. DO NOT EXECUTE. NOT-FOR-EXECUTION.**

## Source incident

In May 2022 the PyPI package `ctx` (a tiny utility that returns a small
dict-like context object, last legitimately released in 2014) was
re-published under a hijacked maintainer account. The new releases
(`0.2.2` and a same-day `0.2.6`) carried a `setup.py` that read the
target machine's `~/.aws/credentials`, `~/.docker/config.json`,
`~/.netrc`, and environment variables, then POSTed everything to an
attacker-controlled endpoint. The same actor pulled the same trick on
the PHP `phpass` library at Packagist on the same day.

Reference:
https://www.bleepingcomputer.com/news/security/pypi-package-ctx-and-php-library-phpass-hijacked-to-steal-aws-keys/

## Why this reconstruction matters for apiary

PyPI does not have explicit lifecycle scripts the way npm does. The
equivalent of npm's postinstall hook is `setup.py` itself: pip executes
it during sdist install with full user privileges. The apiary policy
gate treats every PyPI sdist as carrying a synthetic `setup_py`
install-script hook so the install-scripts rule fires whenever an
sdist (rather than a wheel) is the only distribution. ctx 0.2.2
shipped as an sdist; the install-script rule blocks it on the same
mechanism that catches npm postinstall payloads.

## What this reconstruction contains

- `setup.py` - faithful SHAPE of the malicious code with all
  exfiltration targets replaced by `exfil-archive.example.invalid`
- `ctx/__init__.py` - the legitimate-looking module surface
- `README.md` - this file

## What this reconstruction does not contain

- working exfiltration code
- a real callback URL
- credential file reads that actually succeed
- environment-variable harvesting that actually phones home

Every "would have" comment in `setup.py` documents what the real
malware did. The reconstruction logs the intent to stderr and stops
there so a reviewer can read the shape without any network traffic.

## Policy rules that catch this

Run `python demo/run_incident_replay.py --incident ctx-0.2.2` to see
the deterministic policy decision. Expected verdict: **block**, with
the following rule failures:

1. **release_age** - synthetic publish timestamp set to today, under
   the 14-day minimum
2. **install_scripts** - sdist distribution surfaces a synthetic
   `setup_py` hook, which the policy engine treats as a non-trivial
   install command because PyPI's trivial allowlist is intentionally
   empty (any code-at-install in a PyPI sdist warrants review)

The `source_match` rule is also expected to surface as skipped (PyPI
does not publish `gitHead`-style commit pins, so apiary cannot verify
the dist against the repo without a separate lookup).
