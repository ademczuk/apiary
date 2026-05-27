#!/usr/bin/env python3
"""Pre-stage the demo allowlist.

The ``source_match`` policy rule is a stub today. It always returns False,
which means clean baseline packages get a ``quarantine`` verdict instead of
``allow``. The live demo masks that with an allowlist short-circuit in
``demo/run_incident_replay.py``. This script populates the persistent
``quarantine/policy.json`` allowlist with the same packages so a plain
``apiary-quarantine validate`` (and the run_incident_replay allowlist hit
path) both succeed without touching anything else.

Behavior:

  - Reads ``demo/seed_packages.txt`` (one ``pkg@version`` per line, comments OK).
  - Ensures the demo-critical packages are present (adds them if missing).
  - For every spec, calls the same ``add_to_quarantine`` helper the CLI uses
    with ``state="allowlist"``.
  - Validates the resulting policy via ``validate_quarantine_dir``.
  - Idempotent: re-running just rewrites the same entries.

The malicious ``postmark-mcp@1.0.16`` is deliberately NOT added. The demo
proves the policy gate blocks it without a denylist crutch.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apiary_quarantine.workflow import (  # noqa: E402
    DEFAULT_QUARANTINE_DIR,
    add_to_quarantine,
    load_quarantine_db,
    validate_quarantine_dir,
)

DEMO_DIR = Path(__file__).resolve().parent
SEED_FILE = DEMO_DIR / "seed_packages.txt"

# Hard requirements for the Sunday demo. These get force-added to the
# allowlist regardless of whether they are in seed_packages.txt, and the
# seed file is rewritten to include them if any are missing.
DEMO_ALLOWLIST: list[tuple[str, str]] = [
    ("lodash", "4.17.21"),
    ("react", "18.2.0"),
    ("axios", "1.6.2"),
    ("express", "4.18.2"),
    ("typescript", "5.3.3"),
    # The LEGITIMATE pre-compromise postmark-mcp release. Explicit allowlist
    # so the demo's "safe fallback" step lights up green.
    ("postmark-mcp", "1.0.12"),
]

RATIONALE = (
    "Pre-staged for demo - verified clean baseline. "
    "Added by demo/prestage_allowlist.py before the live pitch so the "
    "source_match stub does not produce false quarantine verdicts on "
    "the curated demo packages. Remove this entry once the real "
    "source_match rule lands."
)

_PKG_VER_RE = re.compile(
    r"^(?P<pkg>@?[a-z0-9][\w.\-]*(?:/[a-z0-9][\w.\-]*)?)@(?P<ver>[\w.\-+]+)$",
    re.IGNORECASE,
)


def _parse_seed_file(path: Path) -> list[tuple[str, str]]:
    """Return a list of (package, version) pairs from ``seed_packages.txt``."""
    if not path.exists():
        return []
    out: list[tuple[str, str]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _PKG_VER_RE.match(line)
        if not match:
            print(f"  warn: could not parse seed line: {line!r}", file=sys.stderr)
            continue
        out.append((match.group("pkg"), match.group("ver")))
    return out


def _ensure_seed_entries(path: Path, required: list[tuple[str, str]]) -> int:
    """Append any missing required entries to the seed file. Returns count added."""
    existing = set(_parse_seed_file(path))
    missing = [spec for spec in required if spec not in existing]
    if not missing:
        return 0

    block_lines: list[str] = []
    if path.exists() and not path.read_text(encoding="utf-8").endswith("\n"):
        block_lines.append("")
    block_lines.append("")
    block_lines.append("# Pre-staged demo allowlist (auto-added by prestage_allowlist.py)")
    for pkg, ver in missing:
        block_lines.append(f"{pkg}@{ver}")

    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(block_lines) + "\n")
    return len(missing)


def _collect_allowlist_targets() -> list[tuple[str, str]]:
    """Merge hard-required demo packages with anything parseable in the seed file."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []

    # Hard requirements first so they appear first in printed summary.
    for spec in DEMO_ALLOWLIST:
        if spec not in seen:
            seen.add(spec)
            out.append(spec)

    # Pull anything else from the seed file too, but skip clearly-malicious
    # entries. The seed file ships known-malicious controls for demo loops
    # that are not the same thing as the allowlist.
    KNOWN_MALICIOUS = {
        ("event-stream", "3.3.6"),
        ("eslint-scope", "3.7.2"),
        ("ua-parser-js", "0.7.29"),
        ("rc", "1.2.9"),
        ("coa", "2.0.3"),
    }
    for pkg, ver in _parse_seed_file(SEED_FILE):
        if (pkg, ver) in KNOWN_MALICIOUS:
            continue
        if (pkg, ver) in seen:
            continue
        seen.add((pkg, ver))
        out.append((pkg, ver))

    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="prestage_allowlist",
        description="Populate quarantine/policy.json allowlist for the demo.",
    )
    parser.add_argument(
        "--quarantine-dir",
        type=Path,
        default=DEFAULT_QUARANTINE_DIR,
        help="Path to the quarantine/ directory (default: ./quarantine).",
    )
    parser.add_argument(
        "--seed-file",
        type=Path,
        default=SEED_FILE,
        help="Path to demo/seed_packages.txt.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be added without touching the policy.",
    )
    args = parser.parse_args(argv)

    added_to_seed = _ensure_seed_entries(args.seed_file, DEMO_ALLOWLIST)
    if added_to_seed:
        print(f"Added {added_to_seed} missing required entries to {args.seed_file}")

    targets = _collect_allowlist_targets()
    print(f"Pre-staging {len(targets)} package(s) on the demo allowlist:")
    for pkg, ver in targets:
        print(f"  - {pkg}@{ver}")
    print()

    if args.dry_run:
        print("Dry run; no changes written.")
        return 0

    for pkg, ver in targets:
        try:
            add_to_quarantine(
                pkg,
                ver,
                RATIONALE,
                quarantine_dir=args.quarantine_dir,
                state="allowlist",
            )
        except Exception as exc:  # noqa: BLE001
            print(f"  fail: {pkg}@{ver}: {exc}", file=sys.stderr)
            return 1

    # Validate the resulting layout.
    report = validate_quarantine_dir(args.quarantine_dir)
    if not report.ok:
        print("validation failed after pre-stage:", file=sys.stderr)
        if report.invalid_keys:
            print("  invalid keys:", report.invalid_keys, file=sys.stderr)
        if report.missing_notes:
            print("  missing notes:", report.missing_notes, file=sys.stderr)
        if report.orphan_notes:
            print("  orphan notes:", report.orphan_notes, file=sys.stderr)
        return 1

    db = load_quarantine_db(args.quarantine_dir)
    total = len(db.get("allowlist", {}))
    print()
    print(
        f"Pre-staged {len(targets)} packages for demo. "
        f"Allowlist now contains {total} total entries."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
