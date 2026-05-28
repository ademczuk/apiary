"""Agentic-format training records: simulated tool-use trajectories.

For each VersionPair we know the ground truth: which files changed,
which lifecycle scripts the maintainer added, what the diff looks like.
We use that knowledge to synthesize the OPTIMAL agent trajectory:
exactly the sequence of tool calls (read_file, list_dir,
run_static_analysis) a well-trained auditor would make to reach the
correct verdict, with no wasted steps.

This is "gold trajectory" training data. The fine-tuned model learns to
mimic the trajectory shape (start with package.json, inspect install
scripts if present, sample changed files, emit structured verdict) so
at inference time it issues the same kind of disciplined tool-use
sequence on packages it has never seen.

Pipeline position::

    version_pair_extractor.py -> VersionPair
    agentic_format_builder.py  <-- THIS  -> JSONL multi-turn SFT
    sft_lora.py (tool-use trained adapter)

Format: a ``messages`` array compatible with the chat-template SFT path
already shipping in ``apiary_train/sft_lora.py`` and the Andreas adapter.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Iterator

# Allow run-as-script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apiary_train.version_pair_extractor import (  # noqa: E402
    FileChange,
    VersionPair,
)

logger = logging.getLogger("apiary.agentic_format_builder")


SYSTEM_PROMPT = (
    "You are an apiary security analyst with access to the following tools:\n"
    "- read_file(path: str) -> str           # returns file contents\n"
    "- list_dir(path: str) -> list[str]      # returns entries under path\n"
    "- run_static_analysis(path: str) -> str # returns lint / pattern hits\n"
    "Audit the package version against the Class A compromised-maintainer "
    "threat model. Inspect lifecycle scripts and the diff against the prior "
    "version, then emit a structured JSON verdict matching the apiary "
    "Decision contract: {verdict, threat_class, confidence, reasoning, "
    "findings}."
)

MAX_TOOL_BODY_CHARS = 4 * 1024  # cap each tool-message body
MAX_FILES_TO_SAMPLE = 4  # at most 4 changed files are walked in the trajectory


def _truncate(s: str, cap: int = MAX_TOOL_BODY_CHARS) -> str:
    if len(s) <= cap:
        return s
    return s[: cap - 32] + "\n... [truncated]\n"


def _has_install_script(pair: VersionPair) -> tuple[bool, dict[str, str]]:
    """Return (any_added_or_changed, dict_of_install_script_changes)."""
    before = (
        (pair.package_json_changes or {}).get("before", {}).get("scripts") or {}
    )
    after = (
        (pair.package_json_changes or {}).get("after", {}).get("scripts") or {}
    )
    hooks = ("preinstall", "install", "postinstall")
    changes: dict[str, str] = {}
    for hook in hooks:
        b = before.get(hook)
        a = after.get(hook)
        if b != a:
            changes[hook] = f"before={b!r} after={a!r}"
    return bool(changes), changes


def _pick_evidence_files(pair: VersionPair) -> list[FileChange]:
    """Pick the most informative changed files for the trajectory.

    Priority order:
      1. anything in install / postinstall referenced from package.json
      2. modified files (real diff is more informative than wholesale add)
      3. added files
      4. fall back to lexicographic order
    """
    if not pair.file_changes:
        return []

    install_hint_names = {"postinstall.js", "install.js", "preinstall.js"}

    def _priority(fc: FileChange) -> tuple[int, int, str]:
        path = fc.path
        base = path.rsplit("/", 1)[-1].lower()
        is_install = base in install_hint_names
        kind_rank = {"modified": 0, "added": 1, "removed": 2}.get(fc.change_kind, 3)
        return (0 if is_install else 1, kind_rank, path)

    ranked = sorted(pair.file_changes, key=_priority)
    return ranked[:MAX_FILES_TO_SAMPLE]


def _verdict_for(pair: VersionPair) -> dict[str, Any]:
    """Derive the structured verdict the model should emit at the end."""
    severity = (pair.severity or "unknown").lower()
    if severity == "critical":
        verdict, confidence = "block", 0.95
    elif severity == "high":
        verdict, confidence = "block", 0.88
    elif severity == "medium":
        verdict, confidence = "quarantine", 0.75
    else:
        verdict, confidence = "quarantine", 0.6

    has_install, install_changes = _has_install_script(pair)
    if has_install and severity in ("high", "critical"):
        confidence = min(0.98, confidence + 0.05)

    findings: list[str] = [
        f"GHSA advisory: {(pair.advisory_ids or ['unknown'])[0]}",
        f"Severity tier: {severity}",
        f"File changes between {pair.unpatched_version} and "
        f"{pair.patched_version}: {len(pair.file_changes)}",
    ]
    if install_changes:
        findings.append(
            "Install-script delta: " + "; ".join(
                f"{k}: {v}" for k, v in install_changes.items()
            )
        )
    elif has_install is False:
        findings.append("No lifecycle script delta between versions.")

    reasoning = (
        f"Package {pair.package} at version {pair.unpatched_version} carries a "
        f"confirmed {severity}-severity GHSA advisory. The patched version "
        f"{pair.patched_version} touches {len(pair.file_changes)} file(s) "
        f"relative to the affected version, which is the documented "
        f"remediation path. Class A compromised-maintainer model applies: "
        f"the version bump alters package behavior without a corresponding "
        f"semver-meaningful change in public API."
    )

    return {
        "verdict": verdict,
        "threat_class": "A",
        "confidence": confidence,
        "reasoning": reasoning,
        "findings": findings,
    }


def _initial_observations(pair: VersionPair) -> list[str]:
    """First-pass observations the assistant narrates after reading package.json."""
    before = (pair.package_json_changes or {}).get("before", {}) or {}
    obs: list[str] = []
    repo = before.get("repository")
    if isinstance(repo, dict):
        url = repo.get("url")
        if url:
            obs.append(f"Repository pointer: {url}")
    elif isinstance(repo, str) and repo:
        obs.append(f"Repository pointer: {repo}")
    scripts = before.get("scripts") or {}
    for hook in ("preinstall", "install", "postinstall"):
        if scripts.get(hook):
            obs.append(f"{hook} script present: {scripts[hook][:120]!r}")
    if not obs:
        obs.append("No install scripts declared in package.json.")
    return obs


def _list_dir_response(pair: VersionPair) -> str:
    """Synthesize a plausible directory listing from the changed-file set.

    We do not have the full tree available offline, so we approximate by
    listing the top-level directories implied by the diff plus a few
    canonical entries. The training signal is the SHAPE of the call
    sequence, not the exact directory listing.
    """
    top: set[str] = set()
    for fc in pair.file_changes:
        head = fc.path.split("/", 1)[0]
        top.add(head)
    base = sorted(top) or ["src", "lib"]
    canonical = ["package.json", "README.md", "LICENSE"]
    listing = sorted(set(canonical + base))
    return json.dumps(listing, ensure_ascii=False)


def to_agentic_record(pair: VersionPair) -> dict[str, Any]:
    """Build the multi-turn messages record for one VersionPair.

    The trajectory is deterministic given the pair: read package.json,
    list_dir, optionally inspect each install script, then sample the
    most informative changed files in priority order, and finally emit
    the verdict. The model trained on this signal learns to issue the
    same disciplined sequence on packages it has not seen.
    """
    advisory = (pair.advisory_ids or ["unknown"])[0]
    user_msg = (
        f"Audit npm package version against Class A compromised-maintainer "
        f"threat model.\n"
        f"\n"
        f"Package: {pair.package}\n"
        f"Version: {pair.unpatched_version}\n"
        f"Last known safe version: {pair.patched_version}\n"
        f"Advisory: {advisory}\n"
        f"Severity: {pair.severity}\n"
        f"\n"
        f"Use the tools to gather evidence, then emit the structured verdict."
    )

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_msg},
    ]

    # Step 1: read package.json (always)
    messages.append(
        {
            "role": "assistant",
            "content": (
                "I will start by reading package.json to inspect lifecycle "
                "scripts, dependencies, and the repository pointer.\n"
                "<tool_call>read_file(\"package.json\")</tool_call>"
            ),
        }
    )
    before_pkg = (pair.package_json_changes or {}).get("before", {}) or {}
    messages.append(
        {
            "role": "tool",
            "content": _truncate(json.dumps(before_pkg, ensure_ascii=False, indent=2)),
        }
    )

    # Step 2: narrate observations and list_dir
    obs = _initial_observations(pair)
    messages.append(
        {
            "role": "assistant",
            "content": (
                "Observations from package.json:\n"
                + "\n".join(f"- {o}" for o in obs)
                + "\n\nNext I will list the package root to identify which "
                "source files exist.\n"
                "<tool_call>list_dir(\".\")</tool_call>"
            ),
        }
    )
    messages.append(
        {
            "role": "tool",
            "content": _truncate(_list_dir_response(pair)),
        }
    )

    # Step 3: optionally inspect install scripts
    has_install, install_changes = _has_install_script(pair)
    if has_install:
        scripts_added = [
            hook for hook, v in install_changes.items() if v.startswith("before=None")
        ]
        if scripts_added:
            target = scripts_added[0]
            file_guess = f"{target}.js"
            messages.append(
                {
                    "role": "assistant",
                    "content": (
                        f"Install-script delta detected on hook {target!r}. "
                        f"Reading the install script.\n"
                        f"<tool_call>read_file({file_guess!r})</tool_call>"
                    ),
                }
            )
            messages.append(
                {
                    "role": "tool",
                    "content": _truncate(
                        f"// {file_guess} - synthetic excerpt for training\n"
                        f"// (real file content unavailable offline; install-"
                        f"script presence confirmed via package.json delta)\n"
                    ),
                }
            )

    # Step 4: sample evidence files via the diff
    for fc in _pick_evidence_files(pair):
        verb = {
            "added": "added in the affected version",
            "removed": "removed in the patched version",
            "modified": "modified in the patched version",
        }[fc.change_kind]
        messages.append(
            {
                "role": "assistant",
                "content": (
                    f"Inspecting {fc.path} ({verb}, "
                    f"+{fc.added_lines}/-{fc.removed_lines}).\n"
                    f"<tool_call>read_file({fc.path!r})</tool_call>"
                ),
            }
        )
        messages.append(
            {
                "role": "tool",
                "content": _truncate(fc.unified_diff or "(no unified diff)"),
            }
        )

    # Step 5: static analysis sweep (single call)
    messages.append(
        {
            "role": "assistant",
            "content": (
                "Running the static-analysis sweep over the package root.\n"
                "<tool_call>run_static_analysis(\".\")</tool_call>"
            ),
        }
    )
    sa_summary = (
        f"static_analysis.summary: {len(pair.file_changes)} files differ "
        f"from {pair.patched_version}; "
        f"{'install_script_delta' if has_install else 'no_install_delta'}; "
        f"advisory={advisory}; severity={pair.severity}"
    )
    messages.append({"role": "tool", "content": _truncate(sa_summary)})

    # Step 6: emit verdict
    verdict = _verdict_for(pair)
    messages.append(
        {
            "role": "assistant",
            "content": json.dumps(verdict, ensure_ascii=False, indent=2),
        }
    )

    return {
        "messages": messages,
        "meta": {
            "source": "version_pair_agentic",
            "package": pair.package,
            "unpatched_version": pair.unpatched_version,
            "patched_version": pair.patched_version,
            "advisory_id": advisory,
            "severity": pair.severity,
            "n_tool_calls": sum(
                1
                for m in messages
                if m["role"] == "assistant" and "<tool_call>" in m["content"]
            ),
        },
    }


def _iter_pairs(input_root: Path) -> Iterator[VersionPair]:
    for pair_json in input_root.rglob("pair.json"):
        try:
            data = json.loads(pair_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("bad pair.json skipped: %s (%s)", pair_json, exc)
            continue
        if data.get("extraction_method") != "tarball_diff":
            continue
        file_changes = [
            FileChange(**fc) for fc in (data.get("file_changes") or [])
        ]
        yield VersionPair(
            package=data["package"],
            unpatched_version=data["unpatched_version"],
            patched_version=data["patched_version"],
            advisory_ids=list(data.get("advisory_ids") or []),
            severity=data.get("severity") or "unknown",
            file_changes=file_changes,
            package_json_changes=data.get("package_json_changes") or {},
            extraction_method=data["extraction_method"],
            notes=list(data.get("notes") or []),
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--version-pairs",
        type=Path,
        default=Path("data/raw/version-pairs/"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/sft/agentic-trajectories.jsonl"),
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if not args.version_pairs.is_dir():
        logger.error("version-pairs dir not found: %s", args.version_pairs)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    n_written = 0
    with args.output.open("w", encoding="utf-8") as fh:
        for pair in _iter_pairs(args.version_pairs):
            record = to_agentic_record(pair)
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            n_written += 1
    logger.info(
        "wrote %d agentic-trajectory records to %s", n_written, args.output
    )
    return 0


__all__ = ["to_agentic_record"]


if __name__ == "__main__":
    sys.exit(main())
