"""Policy engine for the Apiary npm registry proxy.

Each rule is a small function returning ``(passed, reason)``. The composite
``decide_policy`` aggregates rule outcomes into a ``PolicyDecision`` with a
single verdict (allow / quarantine / block) and an evidence list. The proxy
calls ``decide_policy`` before serving any tarball.

Block conditions (any one trips):
    * Release age below the configured minimum (default 14 days).
    * Lifecycle scripts contain non-trivial commands.

Quarantine conditions (any one trips, when not already blocked):
    * dist.integrity could not be verified.
    * repository.url / gitHead present but source match not yet performed.

Allow only when every rule passes.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Literal

from apiary_policy.checksums import verify_integrity

logger = logging.getLogger("apiary.policy")

Verdict = Literal["allow", "quarantine", "block"]

# Lifecycle hooks npm runs automatically; anything non-trivial in these scripts
# is treated as a block-worthy supply-chain risk.
LIFECYCLE_HOOKS: tuple[str, ...] = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
)

# Single-token commands we will tolerate inside lifecycle scripts. Anything
# else (shell metachars, multi-arg invocations, eval-like primitives) is a
# block.
TRIVIAL_LIFECYCLE_ALLOWLIST: frozenset[str] = frozenset(
    {
        "node-gyp",
        "node-gyp-build",
        "prebuild-install",
        "echo",
        "true",
        "exit",
    }
)


@dataclass
class PolicyDecision:
    """Composite policy verdict returned by ``decide_policy``."""

    verdict: Verdict
    failed_rules: list[str] = field(default_factory=list)
    passed_rules: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


# ----------------------------------------------------------------------------
# Individual rules
# ----------------------------------------------------------------------------


def check_release_age(
    metadata: dict[str, Any], version: str, min_age_days: int = 14
) -> tuple[bool, str]:
    """Reject versions younger than ``min_age_days``.

    npm metadata stores publish timestamps under ``time[version]`` as ISO 8601
    strings. A missing entry is treated as a failure so we never serve a
    package whose publish date we cannot verify.
    """
    times = metadata.get("time") or {}
    raw_ts = times.get(version)
    if not raw_ts:
        return False, f"missing publish timestamp for {version}"

    try:
        published = dt.datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False, f"unparseable publish timestamp: {raw_ts!r}"

    now = dt.datetime.now(dt.timezone.utc)
    if published.tzinfo is None:
        published = published.replace(tzinfo=dt.timezone.utc)
    age_days = (now - published).total_seconds() / 86400.0

    if age_days < min_age_days:
        return False, f"released {age_days:.1f}d ago, minimum is {min_age_days}d"
    return True, f"released {age_days:.1f}d ago"


def _is_trivial_script(command: str) -> bool:
    """Return True when ``command`` is a single-token, allowlisted invocation."""
    if not command or not command.strip():
        return True
    if any(ch in command for ch in ";&|`$<>"):
        return False
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return False
    if not parts:
        return True
    head = parts[0]
    # Allow forms like ``node-gyp rebuild`` (two-token, allowlisted head).
    if head in TRIVIAL_LIFECYCLE_ALLOWLIST and len(parts) <= 3:
        return True
    return False


def check_install_scripts(package_json: dict[str, Any]) -> tuple[bool, str]:
    """Reject packages whose lifecycle scripts are non-trivial."""
    scripts = package_json.get("scripts") or {}
    if not isinstance(scripts, dict):
        return False, "scripts field is not an object"

    offenders: list[str] = []
    for hook in LIFECYCLE_HOOKS:
        cmd = scripts.get(hook)
        if cmd and not _is_trivial_script(str(cmd)):
            offenders.append(f"{hook}={cmd!r}")
    if offenders:
        return False, "non-trivial lifecycle scripts: " + "; ".join(offenders)
    return True, "lifecycle scripts trivial or absent"


def check_checksum(
    metadata: dict[str, Any], version: str, tarball_bytes: bytes | None
) -> tuple[bool, str]:
    """Verify the dist.integrity declared for the version matches the tarball."""
    versions = metadata.get("versions") or {}
    version_block = versions.get(version) or {}
    dist = version_block.get("dist") or {}
    integrity = dist.get("integrity")

    if not integrity:
        return False, "dist.integrity missing from metadata"
    if tarball_bytes is None:
        return False, "tarball bytes not yet fetched; cannot verify"

    result = verify_integrity(integrity, tarball_bytes)
    if result.error:
        return False, f"integrity parse error: {result.error}"
    if not result.matches:
        return (
            False,
            f"checksum mismatch: expected {result.expected_b64[:16]}... "
            f"got {result.actual_b64[:16]}...",
        )
    return True, f"{result.algo} verified"


def check_known_quarantine(
    package: str, version: str, quarantine_db: dict[str, Any] | None
) -> tuple[bool, str]:
    """Fail when ``package@version`` is explicitly quarantined or blocked."""
    if not quarantine_db:
        return True, "no quarantine db loaded"

    key = f"{package}@{version}"
    blocked = quarantine_db.get("blocked") or {}
    quarantined = quarantine_db.get("quarantined") or {}

    if key in blocked:
        return False, f"explicitly blocked: {blocked[key].get('reason', 'no reason')}"
    if key in quarantined:
        return (
            False,
            f"explicitly quarantined: {quarantined[key].get('reason', 'no reason')}",
        )
    return True, "not in quarantine db"


_REPO_URL_RE = re.compile(r"^(git\+)?(https?|ssh|git)://", re.IGNORECASE)


def check_source_match(
    metadata: dict[str, Any], version: str
) -> tuple[bool, str]:
    """Stub: confirm we have the pointers we would need for a real source match.

    A production implementation would check out the upstream repo at
    ``gitHead`` and diff against the tarball. For the hackathon proxy we just
    record whether the inputs are present and mark the result as unverified
    so the caller routes the package to quarantine rather than allow.
    """
    versions = metadata.get("versions") or {}
    version_block = versions.get(version) or {}
    repository = version_block.get("repository")
    git_head = version_block.get("gitHead")

    repo_url: str | None = None
    if isinstance(repository, dict):
        repo_url = repository.get("url")
    elif isinstance(repository, str):
        repo_url = repository

    if not repo_url or not isinstance(repo_url, str):
        return False, "repository.url missing; source-match-not-verified"
    if not _REPO_URL_RE.match(repo_url):
        return False, f"repository.url not a recognised VCS URL: {repo_url!r}"
    if not git_head:
        return False, "gitHead missing; source-match-not-verified"

    # We have the inputs but the actual diff step is not implemented yet.
    return False, "source-match-not-verified (inputs present but diff stage TODO)"


# ----------------------------------------------------------------------------
# Composite decision
# ----------------------------------------------------------------------------


def _extract_package_json(metadata: dict[str, Any], version: str) -> dict[str, Any]:
    versions = metadata.get("versions") or {}
    block = versions.get(version)
    if isinstance(block, dict):
        return block
    return {}


def decide_policy(
    package: str,
    version: str,
    metadata: dict[str, Any],
    tarball_bytes: bytes | None = None,
    quarantine_db: dict[str, Any] | None = None,
    min_age_days: int = 14,
) -> PolicyDecision:
    """Run every rule and aggregate the outcomes into a single verdict."""
    package_json = _extract_package_json(metadata, version)

    rules: list[tuple[str, tuple[bool, str]]] = [
        ("known_quarantine", check_known_quarantine(package, version, quarantine_db)),
        ("release_age", check_release_age(metadata, version, min_age_days)),
        ("install_scripts", check_install_scripts(package_json)),
        ("checksum", check_checksum(metadata, version, tarball_bytes)),
        ("source_match", check_source_match(metadata, version)),
    ]

    failed: list[str] = []
    passed: list[str] = []
    evidence: list[str] = []
    for name, (ok, reason) in rules:
        if ok:
            passed.append(name)
        else:
            failed.append(name)
        evidence.append(f"{name}: {reason}")

    # Block on critical failures (release age, lifecycle scripts, known block).
    block_rules = {"release_age", "install_scripts", "known_quarantine"}
    if any(r in block_rules for r in failed):
        verdict: Verdict = "block"
    elif failed:
        verdict = "quarantine"
    else:
        verdict = "allow"

    logger.info(
        "policy %s@%s -> %s (failed=%s)",
        package,
        version,
        verdict,
        ",".join(failed) or "none",
    )

    return PolicyDecision(
        verdict=verdict,
        failed_rules=failed,
        passed_rules=passed,
        evidence=evidence,
    )
