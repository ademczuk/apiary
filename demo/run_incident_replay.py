#!/usr/bin/env python3
"""Retroactive incident replay driver for the Apiary policy gate.

Runs the deterministic Apiary policy engine against faithful reconstructions
of real-world npm supply-chain incidents stored under demo/incidents/, then
renders an insurance-grade Control Evidence Memo from the result.

Three incidents ship in-tree:

    --incident postmark-mcp-1.0.16   the September 2025 malicious release
    --incident postmark-mcp-1.0.12   the legitimate prior version
    --incident lodash-4.17.21        clean popular-package baseline

The runner is fully offline. LLM audit is invoked only when the
APIARY_LLM_BACKEND env var selects a configured backend; otherwise the
memo records "Not performed" and the demo still completes end to end.

Output is colorized and intentionally dramatic for live judging.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

# Allow running directly from a checkout without `pip install -e .`
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from apiary_policy.rules import decide_policy, PolicyDecision  # noqa: E402
from apiary_quarantine.workflow import (  # noqa: E402
    add_to_quarantine,
    build_memo_context,
    render_control_evidence_memo,
)

INCIDENTS_DIR = Path(__file__).resolve().parent / "incidents"
DEFAULT_MEMO_DIR = Path(__file__).resolve().parent / "outputs"

# Real-world loss reference (cite-on-the-slide number).
INSURANCE_LOSS_USD_M = 4.91
INSURANCE_MTTC_DAYS = 267
INSURANCE_SOURCE = (
    "IBM Cost of a Data Breach Report 2024 - "
    "https://www.ibm.com/reports/data-breach"
)


# ----------------------------------------------------------------------------
# Tiny ANSI color helpers (no rich dependency needed for the basic demo)
# ----------------------------------------------------------------------------


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return os.environ.get("FORCE_COLOR", "") != ""
    return True


_USE_COLOR = _supports_color()


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\x1b[{code}m{text}\x1b[0m"


def red(t: str) -> str:
    return _c("31;1", t)


def green(t: str) -> str:
    return _c("32;1", t)


def yellow(t: str) -> str:
    return _c("33;1", t)


def cyan(t: str) -> str:
    return _c("36;1", t)


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


# ----------------------------------------------------------------------------
# Incident loading and synthetic-metadata builders
# ----------------------------------------------------------------------------


def _load_package_json(incident_dir: Path) -> dict[str, Any]:
    pj_path = incident_dir / "package.json"
    if not pj_path.exists():
        raise FileNotFoundError(f"package.json missing under {incident_dir}")
    return json.loads(pj_path.read_text(encoding="utf-8"))


def _build_npm_metadata(
    package_json: dict[str, Any],
    *,
    is_fresh: bool,
) -> dict[str, Any]:
    """Build a faux npm registry metadata blob.

    ``is_fresh=True`` stamps the publish timestamp at ``now`` so the
    release-age rule fires. ``False`` stamps it 60 days back so the rule
    passes (and other rules carry the demo).
    """
    name = package_json.get("name", "<unknown>")
    version = package_json.get("version", "0.0.0")

    if is_fresh:
        published = dt.datetime.now(dt.timezone.utc)
    else:
        published = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=60)

    version_block: dict[str, Any] = dict(package_json)
    # npm metadata typically carries a dist.integrity hash. We fabricate one
    # so the checksum rule can be exercised end-to-end.
    fake_tarball = json.dumps(package_json, sort_keys=True).encode("utf-8")
    digest = hashlib.sha512(fake_tarball).digest()
    import base64

    integrity = "sha512-" + base64.b64encode(digest).decode("ascii")
    version_block["dist"] = {
        "tarball": (
            f"https://registry.npmjs.org/{name}/-/"
            f"{name}-{version}.tgz"
        ),
        "integrity": integrity,
    }

    metadata = {
        "name": name,
        "time": {
            version: published.isoformat(),
        },
        "versions": {
            version: version_block,
        },
    }
    return metadata, fake_tarball


# ----------------------------------------------------------------------------
# Decision -> memo bridge
# ----------------------------------------------------------------------------


def _decision_to_rules(decision: PolicyDecision) -> list[dict[str, Any]]:
    """Flatten a ``PolicyDecision`` evidence list into memo-template rows."""
    passed = set(decision.passed_rules)
    rows: list[dict[str, Any]] = []
    for entry in decision.evidence:
        name, _, detail = entry.partition(":")
        name = name.strip()
        detail = detail.strip()
        rows.append(
            {
                "name": name,
                "passed": name in passed,
                "detail": detail,
            }
        )
    return rows


def _loss_path_for(package: str, decision: str) -> tuple[str, str]:
    """Return (loss_path, incident_class) used in the memo insurance block."""
    if decision == "block":
        if package == "postmark-mcp":
            return (
                "credential and transactional-email exfiltration via "
                "malicious postinstall script",
                "npm-supply-chain-credential-theft",
            )
        return (
            "supply-chain dependency compromise",
            "npm-supply-chain",
        )
    return (
        "no loss path - package cleared by policy controls",
        "n/a",
    )


# ----------------------------------------------------------------------------
# Optional LLM audit
# ----------------------------------------------------------------------------


def _run_llm_audit(incident_dir: Path) -> str | None:
    """Invoke the configured LLM audit backend, if any.

    Gracefully returns None when the backend env vars are missing or the
    optional dependency is not installed. The demo never fails because of
    a missing LLM.
    """
    backend_name = os.environ.get("APIARY_LLM_BACKEND")
    if not backend_name:
        return None

    try:
        from apiary_auditors.llm_audit import (
            build_audit_prompt,
            get_backend,
        )
    except Exception as exc:
        return f"LLM audit unavailable: {exc}"

    try:
        prompt = build_audit_prompt(incident_dir)
        kwargs: dict[str, Any] = {}
        if backend_name == "dwarfstar":
            kwargs["base_url"] = os.environ.get(
                "APIARY_LLM_BASE_URL", "http://localhost:8080"
            )
            kwargs["model"] = os.environ.get(
                "APIARY_LLM_MODEL", "deepseek-coder"
            )
        elif backend_name == "ollama":
            kwargs["base_url"] = os.environ.get(
                "APIARY_LLM_BASE_URL", "http://localhost:11434"
            )
            kwargs["model"] = os.environ.get(
                "APIARY_LLM_MODEL", "deepseek-coder:6.7b"
            )
        backend = get_backend(backend_name, **kwargs)
        result = backend.audit(prompt)
        findings = "\n  - ".join(result.findings) if result.findings else "(none listed)"
        return (
            f"Verdict: **{result.verdict}** "
            f"(confidence {result.confidence:.2f})\n\n"
            f"Reasoning: {result.reasoning}\n\n"
            f"Findings:\n  - {findings}"
        )
    except Exception as exc:
        return f"LLM audit attempted but failed: {exc}"


# ----------------------------------------------------------------------------
# Pretty-print routines
# ----------------------------------------------------------------------------


def _print_header(
    incident: str, package: str, version: str, threat_class: str = "A"
) -> None:
    bar = "=" * 70
    threat_descriptions = {
        "A": "Compromised-Maintainer Version Bump",
        "B": "Supply-Chain Malware (typosquatting / dep confusion)",
        "C": "Novel Vulnerability Discovery",
    }
    desc = threat_descriptions.get(threat_class, "")
    print()
    print(bold(bar))
    print(bold(f"  APIARY INCIDENT REPLAY: {incident}"))
    print(bold(f"  Package: {package}@{version}"))
    print(bold(f"  Threat class: {threat_class} ({desc})"))
    print(bold(bar))
    print()


def _print_rule_table(decision: PolicyDecision) -> None:
    print(cyan("Policy rule evaluation:"))
    print()
    passed = set(decision.passed_rules)
    for entry in decision.evidence:
        name, _, detail = entry.partition(":")
        name = name.strip()
        detail = detail.strip()
        if name in passed:
            tag = green("  PASS  ")
        else:
            tag = red("  FAIL  ")
        print(f"  [{tag}] {bold(name):<28} {dim(detail)}")
    print()


def _print_verdict(decision: PolicyDecision) -> None:
    verdict = decision.verdict
    if verdict == "block":
        banner = red(f"  VERDICT: BLOCK  -  installation refused")
    elif verdict == "quarantine":
        banner = yellow(f"  VERDICT: QUARANTINE  -  held for review")
    else:
        banner = green(f"  VERDICT: ALLOW  -  package cleared")
    bar = "-" * 70
    print(bar)
    print(banner)
    print(bar)
    print()


def _print_safe_fallback(package: str, blocked_version: str) -> None:
    if package != "postmark-mcp":
        return
    print(cyan("Safe fallback:"))
    print(
        f"  {package}@1.0.12 is the last known-clean release "
        f"(allow-listed by Apiary)."
    )
    print(f"  Suggested install: {bold(f'npm install {package}@1.0.12')}")
    print()


def _print_insurance_footer(verdict: str) -> None:
    bar = "-" * 70
    print(bar)
    print(cyan("Insurance / loss-prevention summary:"))
    print(
        f"  This incident replay demonstrates a control that prevents an "
        f"estimated USD {INSURANCE_LOSS_USD_M:.2f}M cyber-claim event class."
    )
    print(
        f"  Mean time to identify and contain a supply-chain compromise: "
        f"{INSURANCE_MTTC_DAYS} days."
    )
    print(f"  Source: {INSURANCE_SOURCE}")
    if verdict == "block":
        print(green("  Apiary blocked the install before any payload ran."))
    print(bar)
    print()


# ----------------------------------------------------------------------------
# Top-level orchestration
# ----------------------------------------------------------------------------


def run_incident(
    incident: str,
    *,
    memo_dir: Path = DEFAULT_MEMO_DIR,
    quarantine_dir: Path | None = None,
    quiet: bool = False,
) -> tuple[PolicyDecision, Path]:
    """Run the policy gate against an incident and write the audit memo.

    Returns the policy decision and the path of the generated memo file.
    """
    incident_dir = INCIDENTS_DIR / incident
    if not incident_dir.exists():
        raise FileNotFoundError(f"unknown incident: {incident}")

    package_json = _load_package_json(incident_dir)
    package = package_json.get("name", incident)
    version = package_json.get("version", "0.0.0")

    # postmark-mcp-1.0.16 is the "fresh malicious release" scenario.
    # The other two get a 60-day-old timestamp so they clear release-age.
    is_fresh = incident == "postmark-mcp-1.0.16"
    metadata, fake_tarball = _build_npm_metadata(
        package_json, is_fresh=is_fresh
    )

    # Apply known-good allowlist for the safe fallback path.
    quarantine_db = {
        "blocked": {},
        "quarantined": {},
        "allowlist": {
            "postmark-mcp@1.0.12": {
                "reason": "Pre-compromise release; manually allow-listed for demo.",
                "added": dt.datetime.now(dt.timezone.utc).isoformat(),
            },
            "lodash@4.17.21": {
                "reason": "Stable popular release; baseline known-good.",
                "added": dt.datetime.now(dt.timezone.utc).isoformat(),
            },
        },
    }

    # ModuleWarden threat-class taxonomy. All three in-tree incidents are
    # Class A (Compromised-Maintainer Version Bump); the postmark-mcp 1.0.16
    # case is the textbook example. Override here when other incidents land.
    threat_class = "A"

    if not quiet:
        _print_header(incident, package, version, threat_class=threat_class)

    key = f"{package}@{version}"
    allowlisted = key in quarantine_db.get("allowlist", {})

    decision = decide_policy(
        package=package,
        version=version,
        metadata=metadata,
        tarball_bytes=fake_tarball,
        quarantine_db=None,
    )

    # Demo allowlist short-circuit. The production source_match rule is a
    # stub that always returns False, which would mask the demo's clean
    # baselines as "quarantine". An explicit allowlist hit converts a
    # quarantine verdict to allow and adds a passed-rule marker.
    if allowlisted and decision.verdict == "quarantine":
        original_evidence = list(decision.evidence)
        decision = PolicyDecision(
            verdict="allow",
            failed_rules=[],
            passed_rules=decision.passed_rules + ["allowlist_override"],
            evidence=original_evidence + [
                f"allowlist_override: {key} is on the curated allowlist; "
                f"source_match stub bypassed"
            ],
        )

    if not quiet:
        _print_rule_table(decision)
        _print_verdict(decision)

    # Optional LLM audit (gracefully degrades when no backend configured).
    llm_audit = _run_llm_audit(incident_dir)

    # Build and render the Control Evidence Memo.
    rules = _decision_to_rules(decision)
    loss_path, incident_class = _loss_path_for(package, decision.verdict)
    metadata_sha256 = hashlib.sha256(
        json.dumps(metadata, sort_keys=True).encode("utf-8")
    ).hexdigest()
    tarball_sha512 = hashlib.sha512(fake_tarball).hexdigest()

    context = build_memo_context(
        package=package,
        version=version,
        decision=decision.verdict,
        rules=rules,
        loss_path=loss_path,
        incident_class=incident_class,
        llm_audit=llm_audit,
        tarball_sha512=tarball_sha512,
        metadata_sha256=metadata_sha256,
        threat_class=threat_class,
    )
    memo_text = render_control_evidence_memo(context)

    memo_dir.mkdir(parents=True, exist_ok=True)
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    memo_name = f"{package.replace('/', '__')}-{version}__{today}.md"
    memo_path = memo_dir / memo_name
    memo_path.write_text(memo_text, encoding="utf-8")

    if not quiet:
        print(cyan("Audit memo written:"))
        print(f"  {memo_path}")
        print()
        _print_safe_fallback(package, version)
        _print_insurance_footer(decision.verdict)

    return decision, memo_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apiary-incident-replay",
        description=(
            "Replay a real-world npm supply-chain incident against the "
            "Apiary policy gate and produce a Control Evidence Memo."
        ),
    )
    parser.add_argument(
        "--incident",
        required=True,
        choices=[
            "postmark-mcp-1.0.16",
            "postmark-mcp-1.0.12",
            "lodash-4.17.21",
        ],
        help="Which incident reconstruction to replay.",
    )
    parser.add_argument(
        "--memo-dir",
        type=Path,
        default=DEFAULT_MEMO_DIR,
        help="Where to write the rendered Control Evidence Memo.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress pretty-printed demo output (machine-readable mode).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON summary of the decision to stdout (suppresses pretty output).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    quiet = args.quiet or args.json
    decision, memo_path = run_incident(
        args.incident,
        memo_dir=args.memo_dir,
        quiet=quiet,
    )
    if args.json:
        payload = {
            "incident": args.incident,
            "verdict": decision.verdict,
            "failed_rules": decision.failed_rules,
            "passed_rules": decision.passed_rules,
            "memo_path": str(memo_path),
        }
        print(json.dumps(payload, indent=2))
    # Exit code mirrors the verdict so CI can branch on it.
    if decision.verdict == "block":
        return 2
    if decision.verdict == "quarantine":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
