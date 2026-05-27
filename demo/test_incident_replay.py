"""Smoke test for the incident replay driver.

Runs each in-tree incident through ``run_incident`` and compares the
verdict, failed/passed rule sets, and a normalized form of the rendered
Control Evidence Memo against the goldens stored under
``demo/incidents/expected-outputs/``.

Run directly:

    python demo/test_incident_replay.py

Or via pytest:

    pytest demo/test_incident_replay.py
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from demo.run_incident_replay import run_incident  # noqa: E402

EXPECTED_DIR = Path(__file__).resolve().parent / "incidents" / "expected-outputs"

INCIDENTS = (
    "postmark-mcp-1.0.16",
    "postmark-mcp-1.0.12",
    "lodash-4.17.21",
)


def _normalize_memo(text: str) -> str:
    """Replace volatile fields (timestamp, hashes) with sentinels."""
    text = re.sub(
        r"\*\*Evaluated:\*\* [^\n]+",
        "**Evaluated:** <TIMESTAMP>",
        text,
    )
    text = re.sub(
        r"Package tarball SHA-512: `[0-9a-f]+`",
        "Package tarball SHA-512: `<SHA512>`",
        text,
    )
    text = re.sub(
        r"Metadata snapshot SHA-256: `[0-9a-f]+`",
        "Metadata snapshot SHA-256: `<SHA256>`",
        text,
    )
    return text


def _check_decision(incident: str, tmpdir: Path) -> list[str]:
    """Run the incident; return a list of error strings (empty == pass)."""
    errors: list[str] = []
    decision, memo_path = run_incident(
        incident, memo_dir=tmpdir, quiet=True
    )

    expected_path = EXPECTED_DIR / f"{incident}.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))

    if decision.verdict != expected["verdict"]:
        errors.append(
            f"{incident}: verdict mismatch: "
            f"got {decision.verdict!r}, expected {expected['verdict']!r}"
        )
    if sorted(decision.failed_rules) != sorted(expected["failed_rules"]):
        errors.append(
            f"{incident}: failed_rules mismatch: "
            f"got {decision.failed_rules}, expected {expected['failed_rules']}"
        )
    if sorted(decision.passed_rules) != sorted(expected["passed_rules"]):
        errors.append(
            f"{incident}: passed_rules mismatch: "
            f"got {decision.passed_rules}, expected {expected['passed_rules']}"
        )

    # Optional memo golden comparison (only for the headline incident).
    memo_golden = EXPECTED_DIR / f"{incident}.memo.md"
    if memo_golden.exists():
        actual = _normalize_memo(memo_path.read_text(encoding="utf-8"))
        expected_memo = memo_golden.read_text(encoding="utf-8")
        if actual.strip() != expected_memo.strip():
            errors.append(
                f"{incident}: memo content drift "
                f"(see {memo_path} vs {memo_golden})"
            )

    return errors


def run_all() -> int:
    """Run all incidents; return process exit code (0 on success)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        all_errors: list[str] = []
        for incident in INCIDENTS:
            errors = _check_decision(incident, tmpdir)
            if errors:
                all_errors.extend(errors)
                print(f"FAIL  {incident}")
                for e in errors:
                    print(f"      {e}")
            else:
                print(f"PASS  {incident}")
    if all_errors:
        print(f"\n{len(all_errors)} smoke-test failure(s)")
        return 1
    print("\nAll incident replays match goldens.")
    return 0


# pytest entry points (one per incident keeps reports granular)


def test_postmark_mcp_1_0_16() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        errors = _check_decision("postmark-mcp-1.0.16", Path(tmp))
    assert not errors, "\n".join(errors)


def test_postmark_mcp_1_0_12() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        errors = _check_decision("postmark-mcp-1.0.12", Path(tmp))
    assert not errors, "\n".join(errors)


def test_lodash_4_17_21() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        errors = _check_decision("lodash-4.17.21", Path(tmp))
    assert not errors, "\n".join(errors)


if __name__ == "__main__":
    sys.exit(run_all())
