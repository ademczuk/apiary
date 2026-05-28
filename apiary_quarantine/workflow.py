"""Quarantine workflow with mandatory rationale notes.

Every change to ``quarantine/policy.json`` requires a sibling Markdown file
under ``quarantine/notes/{package}@{version}.md`` describing why. The
``validate`` subcommand is intended for use as a git pre-commit hook so a
silent change to the policy can never land.

Layout:

    quarantine/
        policy.json
        notes/
            lodash@4.17.21.md
            event-stream@3.3.6.md
            ...

policy.json shape:

    {
        "blocked":       { "<pkg@ver>": { "reason": str, "added": iso8601 } },
        "quarantined":   { "<pkg@ver>": { "reason": str, "added": iso8601 } },
        "allowlist":     { "<pkg@ver>": { "reason": str, "added": iso8601 } }
    }
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger("apiary.quarantine")

DEFAULT_QUARANTINE_DIR = Path("quarantine")
POLICY_FILENAME = "policy.json"
NOTES_DIRNAME = "notes"

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
MEMO_TEMPLATE_NAME = "control-evidence-memo.md.j2"
APIARY_VERSION = "0.1.0"
POLICY_VERSION = "1.0"

# Allow scoped npm names (``@scope/name``) plus unscoped names. Versions are
# loosely validated semver-ish strings; the proxy does its own strict parsing.
_PKG_VER_RE = re.compile(
    r"^(?P<pkg>@?[a-z0-9][\w.\-]*(?:/[a-z0-9][\w.\-]*)?)@(?P<ver>[\w.\-+]+)$",
    re.IGNORECASE,
)

State = Literal["blocked", "quarantined", "allowlist"]
ALL_STATES: tuple[State, ...] = ("blocked", "quarantined", "allowlist")


@dataclass
class ValidationReport:
    ok: bool
    missing_notes: list[str]
    orphan_notes: list[str]
    invalid_keys: list[str]


def _empty_policy() -> dict[str, dict[str, Any]]:
    return {state: {} for state in ALL_STATES}


def _ensure_layout(quarantine_dir: Path) -> tuple[Path, Path]:
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    policy_path = quarantine_dir / POLICY_FILENAME
    notes_dir = quarantine_dir / NOTES_DIRNAME
    notes_dir.mkdir(parents=True, exist_ok=True)
    if not policy_path.exists():
        policy_path.write_text(json.dumps(_empty_policy(), indent=2), encoding="utf-8")
    return policy_path, notes_dir


def _note_filename(package: str, version: str) -> str:
    # filesystem-safe slashes from scoped packages
    safe = f"{package}@{version}".replace("/", "__")
    return f"{safe}.md"


def _parse_key(key: str) -> tuple[str, str] | None:
    match = _PKG_VER_RE.match(key)
    if not match:
        return None
    return match.group("pkg"), match.group("ver")


def load_quarantine_db(
    quarantine_dir: Path = DEFAULT_QUARANTINE_DIR,
) -> dict[str, dict[str, Any]]:
    """Read ``policy.json`` and return a normalised lookup dict.

    A missing file is treated as an empty policy. Unknown top-level keys are
    preserved so future extensions do not silently drop user data.
    """
    quarantine_dir = Path(quarantine_dir)
    policy_path = quarantine_dir / POLICY_FILENAME
    if not policy_path.exists():
        return _empty_policy()

    raw = json.loads(policy_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{policy_path} is not a JSON object")

    out: dict[str, dict[str, Any]] = _empty_policy()
    for state in ALL_STATES:
        block = raw.get(state) or {}
        if not isinstance(block, dict):
            raise ValueError(f"{policy_path}: {state!r} is not an object")
        out[state] = dict(block)
    # carry forward any extra top-level keys
    for key, value in raw.items():
        if key not in ALL_STATES:
            out[key] = value
    return out


def _atomic_write_json(path: Path, payload: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def add_to_quarantine(
    package: str,
    version: str,
    rationale_md: str,
    quarantine_dir: Path = DEFAULT_QUARANTINE_DIR,
    state: State = "quarantined",
) -> Path:
    """Add ``package@version`` to the policy in the given state and write its note."""
    if state not in ALL_STATES:
        raise ValueError(f"unknown state: {state}")
    if not rationale_md or len(rationale_md.strip()) < 16:
        raise ValueError("rationale_md must be at least 16 chars of real content")

    quarantine_dir = Path(quarantine_dir)
    policy_path, notes_dir = _ensure_layout(quarantine_dir)
    db = load_quarantine_db(quarantine_dir)
    key = f"{package}@{version}"

    note_path = notes_dir / _note_filename(package, version)
    header = (
        f"# {key}\n\n"
        f"State: {state}\n"
        f"Added: {dt.datetime.now(dt.timezone.utc).isoformat()}\n\n"
    )
    body = rationale_md.strip() + "\n"
    _atomic_write_text(note_path, header + body)

    db[state][key] = {
        "reason": rationale_md.strip().splitlines()[0][:200],
        "added": dt.datetime.now(dt.timezone.utc).isoformat(),
        "note": str(note_path.relative_to(quarantine_dir)),
    }
    _atomic_write_json(policy_path, db)
    logger.info("added %s to %s with note %s", key, state, note_path)
    return note_path


def promote(
    package: str,
    version: str,
    quarantine_dir: Path = DEFAULT_QUARANTINE_DIR,
) -> None:
    """Move ``package@version`` from ``quarantined`` to ``allowlist``.

    Requires the existing rationale note. Refuses to promote a key that is
    not currently quarantined.
    """
    quarantine_dir = Path(quarantine_dir)
    policy_path, notes_dir = _ensure_layout(quarantine_dir)
    db = load_quarantine_db(quarantine_dir)
    key = f"{package}@{version}"

    if key not in db["quarantined"]:
        raise KeyError(f"{key} is not currently quarantined")

    note_path = notes_dir / _note_filename(package, version)
    if not note_path.exists():
        raise FileNotFoundError(
            f"missing rationale note for {key}: expected {note_path}"
        )

    entry = db["quarantined"].pop(key)
    entry["promoted"] = dt.datetime.now(dt.timezone.utc).isoformat()
    db["allowlist"][key] = entry
    _atomic_write_json(policy_path, db)

    # Append a promotion log line to the existing note.
    extra = (
        f"\n---\n\nPromoted: {entry['promoted']}\n"
    )
    with note_path.open("a", encoding="utf-8") as fh:
        fh.write(extra)
    logger.info("promoted %s to allowlist", key)


def validate_quarantine_dir(
    quarantine_dir: Path = DEFAULT_QUARANTINE_DIR,
) -> ValidationReport:
    """Confirm every policy entry has a note and every note has a policy entry."""
    quarantine_dir = Path(quarantine_dir)
    policy_path, notes_dir = _ensure_layout(quarantine_dir)
    db = load_quarantine_db(quarantine_dir)

    invalid: list[str] = []
    expected_notes: set[str] = set()
    for state in ALL_STATES:
        for key in db[state]:
            if _parse_key(key) is None:
                invalid.append(f"{state}:{key}")
                continue
            pkg, ver = _parse_key(key)  # type: ignore[misc]
            expected_notes.add(_note_filename(pkg, ver))

    # README.md is the directory's own documentation; it never corresponds to a
    # policy entry and must not be flagged as an orphan.
    actual_notes = {p.name for p in notes_dir.glob("*.md") if p.name != "README.md"}
    missing = sorted(expected_notes - actual_notes)
    orphans = sorted(actual_notes - expected_notes)

    return ValidationReport(
        ok=not (missing or orphans or invalid),
        missing_notes=missing,
        orphan_notes=orphans,
        invalid_keys=invalid,
    )


# ----------------------------------------------------------------------------
# Control Evidence Memo rendering
# ----------------------------------------------------------------------------


def _plain_text_memo(context: dict[str, Any]) -> str:
    """Plain-text fallback memo used when jinja2 is not installed."""
    rule_lines: list[str] = []
    for rule in context.get("rules", []):
        status = "PASS" if rule.get("passed") else "FAIL"
        rule_lines.append(
            f"- {rule.get('name', '<unnamed>')} - {status}\n"
            f"  - {rule.get('detail', '')}"
        )
    rule_block = "\n".join(rule_lines) if rule_lines else "(none recorded)"

    threat_class = context.get("threat_class", "A")
    threat_class_description = context.get(
        "threat_class_description", "Compromised-Maintainer Version Bump"
    )
    return (
        "# Control Evidence Memo\n"
        f"**Control ID:** {context.get('control_id', '')}\n"
        f"**Package:** {context.get('package', '')}@{context.get('version', '')}\n"
        f"**Decision:** {str(context.get('decision', '')).upper()}\n"
        f"**Threat class:** {threat_class} - {threat_class_description}\n"
        f"**Evaluated:** {context.get('timestamp', '')}\n"
        f"**Policy version:** {context.get('policy_version', '')}\n"
        f"**Evaluator:** apiary {context.get('apiary_version', '')}\n\n"
        "---\n\n"
        "## Decision\n"
        f"{context.get('decision_description', '')}\n\n"
        "## Rule Evaluations\n"
        f"{rule_block}\n\n"
        "## LLM Audit Summary\n"
        f"{context.get('llm_audit') or 'Not performed.'}\n\n"
        "## Insurance / Compliance Notes\n"
        f"- Loss path prevented: {context.get('loss_path', '')}\n"
        f"- Estimated incident class: {context.get('incident_class', '')}\n"
        "- Reference loss model: IBM Cost of a Data Breach Report 2024 "
        "places the average software supply-chain compromise at USD 4.91M "
        "with a 267-day mean time to identify and contain.\n"
    )


def render_control_evidence_memo(context: dict[str, Any]) -> str:
    """Render the insurance-grade Control Evidence Memo.

    Uses Jinja2 when the package is installed; falls back to a plain-text
    template that carries the same load-bearing fields so the audit memo
    never fails to render.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        logger.warning("jinja2 not installed; using plain-text memo fallback")
        return _plain_text_memo(context)

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(disabled_extensions=(".j2",)),
        keep_trailing_newline=True,
    )
    template = env.get_template(MEMO_TEMPLATE_NAME)
    return template.render(**context)


def build_memo_context(
    package: str,
    version: str,
    decision: str,
    rules: list[dict[str, Any]],
    *,
    loss_path: str = "supply-chain dependency compromise",
    incident_class: str = "npm-supply-chain",
    llm_audit: str | None = None,
    tarball_sha512: str = "(not computed)",
    metadata_sha256: str = "(not computed)",
    control_id: str | None = None,
    approver_role: str = "Security Engineering",
    threat_class: str = "A",
) -> dict[str, Any]:
    """Assemble the template context dict from raw policy outputs.

    ``threat_class`` follows ModuleWarden's A/B/C taxonomy. Apiary v1
    primarily targets Class A (Compromised-Maintainer Version Bump);
    Class B (typosquatting / dependency confusion) is not the optimization
    target; Class C (novel vulnerability discovery) is supported through
    pattern checks only.
    """
    # Mirror the THREAT_CLASS_DESCRIPTIONS table from shared.types so the
    # plain-text fallback memo and the Jinja template render the same wording.
    try:
        from shared.types import THREAT_CLASS_DESCRIPTIONS

        threat_class_description = THREAT_CLASS_DESCRIPTIONS.get(
            threat_class, THREAT_CLASS_DESCRIPTIONS["A"]
        )
    except ImportError:
        threat_class_description = "Compromised-Maintainer Version Bump"

    decision_descriptions = {
        "allow": (
            "Package meets all dependency-intake controls and is approved "
            "for installation."
        ),
        "quarantine": (
            "Package fails one or more non-blocking controls and is held "
            "in quarantine pending manual review."
        ),
        "block": (
            "Package fails one or more blocking controls and is refused "
            "service by the registry proxy. Installation is prevented."
        ),
    }
    return {
        "control_id": control_id or f"APIARY-{package}-{version}",
        "package": package,
        "version": version,
        "decision": decision,
        "decision_description": decision_descriptions.get(
            decision, "Decision recorded; no description available."
        ),
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "policy_version": POLICY_VERSION,
        "apiary_version": APIARY_VERSION,
        "rules": rules,
        "llm_audit": llm_audit if llm_audit else "Not performed.",
        "tarball_sha512": tarball_sha512,
        "metadata_sha256": metadata_sha256,
        "approver_role": approver_role,
        "loss_path": loss_path,
        "incident_class": incident_class,
        "threat_class": threat_class,
        "threat_class_description": threat_class_description,
    }


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def _cmd_validate(args: argparse.Namespace) -> int:
    report = validate_quarantine_dir(args.quarantine_dir)
    if report.ok:
        print("quarantine OK")
        return 0
    if report.invalid_keys:
        print("invalid keys:")
        for k in report.invalid_keys:
            print(f"  {k}")
    if report.missing_notes:
        print("missing rationale notes (policy entry without .md):")
        for n in report.missing_notes:
            print(f"  {n}")
    if report.orphan_notes:
        print("orphan notes (.md without policy entry):")
        for n in report.orphan_notes:
            print(f"  {n}")
    return 1


def _cmd_add(args: argparse.Namespace) -> int:
    parsed = _parse_key(args.spec)
    if parsed is None:
        print(f"could not parse {args.spec!r}; expected pkg@version")
        return 2
    pkg, ver = parsed
    note = add_to_quarantine(
        pkg,
        ver,
        args.rationale,
        args.quarantine_dir,
        state=args.state,
    )
    print(f"added {pkg}@{ver}; note at {note}")
    return 0


def _cmd_promote(args: argparse.Namespace) -> int:
    parsed = _parse_key(args.spec)
    if parsed is None:
        print(f"could not parse {args.spec!r}; expected pkg@version")
        return 2
    pkg, ver = parsed
    try:
        promote(pkg, ver, args.quarantine_dir)
    except (KeyError, FileNotFoundError) as exc:
        print(f"promote failed: {exc}")
        return 1
    print(f"promoted {pkg}@{ver} to allowlist")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="apiary-quarantine")
    parser.add_argument(
        "--quarantine-dir",
        type=Path,
        default=DEFAULT_QUARANTINE_DIR,
        help="directory holding policy.json and notes/",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_val = sub.add_parser("validate", help="check notes/policy consistency")
    p_val.set_defaults(func=_cmd_validate)

    p_add = sub.add_parser("add", help="add a package to the policy")
    p_add.add_argument("spec", help="pkg@version (e.g. lodash@4.17.21)")
    p_add.add_argument(
        "--rationale", required=True, help="markdown rationale (at least 16 chars)"
    )
    p_add.add_argument(
        "--state",
        choices=ALL_STATES,
        default="quarantined",
        help="initial state for the entry",
    )
    p_add.set_defaults(func=_cmd_add)

    p_promote = sub.add_parser(
        "promote", help="move a quarantined entry to the allowlist"
    )
    p_promote.add_argument("spec", help="pkg@version")
    p_promote.set_defaults(func=_cmd_promote)

    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
