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
from pathlib import Path
from typing import Any, Literal, Optional

from apiary_policy.checksums import verify_integrity
from apiary_policy.environments import (
    DEFAULT_ENV_NAME,
    EnvironmentPolicy,
    load_environment_policy,
)
from apiary_policy.source_match import check_source_match as _verify_source_match

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
    metadata: dict[str, Any],
    version: str,
    tarball_bytes: bytes | None = None,
    cache_dir: Path | None = None,
) -> Optional[tuple[bool, str]]:
    """Verify the npm tarball matches its upstream repository at ``gitHead``.

    Returns:
        ``(True, reason)``  when the tarball matches the source.
        ``(False, reason)`` when the tarball diverges from source.
        ``None``            when verification could not be performed
                            (missing pointers, unreachable upstream, or no
                            tarball bytes). The caller treats ``None`` as a
                            quarantine-worthy outcome.
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
        return None
    if not _REPO_URL_RE.match(repo_url):
        return None
    if not git_head:
        return None
    if tarball_bytes is None:
        return None

    kwargs: dict[str, Any] = {}
    if cache_dir is not None:
        kwargs["cache_dir"] = cache_dir
    return _verify_source_match(metadata, version, tarball_bytes, **kwargs)


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
    min_age_days: int | None = None,
    environment: str = DEFAULT_ENV_NAME,
    env_config_path: Path | None = None,
    env_policy: EnvironmentPolicy | None = None,
    source_cache_dir: Path | None = None,
) -> PolicyDecision:
    """Run every rule and aggregate the outcomes into a single verdict.

    The optional ``environment`` (or pre-loaded ``env_policy``) controls
    per-env behaviour: minimum release age, lifecycle-script policy, whether
    source-match and checksum are required, fail-open behaviour on audit
    errors, and whether the decision is enforced (``log_only=False``) or
    advisory (``log_only=True``).
    """
    policy = env_policy or load_environment_policy(environment, env_config_path)

    # Effective min release age: explicit caller value wins; otherwise the
    # per-environment default is used.
    effective_min_age = min_age_days if min_age_days is not None else policy.min_release_age_days

    package_json = _extract_package_json(metadata, version)

    rules: list[tuple[str, tuple[bool, str] | None]] = [
        ("known_quarantine", check_known_quarantine(package, version, quarantine_db)),
        ("release_age", check_release_age(metadata, version, effective_min_age)),
        ("install_scripts", check_install_scripts(package_json)),
        ("checksum", check_checksum(metadata, version, tarball_bytes)),
        ("source_match", check_source_match(metadata, version, tarball_bytes, source_cache_dir)),
    ]

    failed: list[str] = []
    passed: list[str] = []
    skipped: list[str] = []
    evidence: list[str] = []
    for name, outcome in rules:
        if outcome is None:
            skipped.append(name)
            evidence.append(f"{name}: skipped (no verdict)")
            continue
        ok, reason = outcome
        if ok:
            passed.append(name)
        else:
            failed.append(name)
        evidence.append(f"{name}: {reason}")

    # Apply per-environment behaviour to lifecycle scripts.
    if "install_scripts" in failed and policy.install_scripts == "allow":
        failed.remove("install_scripts")
        passed.append("install_scripts")
    elif "install_scripts" in failed and policy.install_scripts == "warn":
        failed.remove("install_scripts")
        skipped.append("install_scripts")

    # If the environment does not require checksum / source-match, a missing
    # verdict (skipped) does not penalise. A FAILED checksum is still a block
    # because it indicates tampering, never an absent verdict.
    if not policy.require_checksum and "checksum" in skipped:
        pass  # already skipped, no action
    if not policy.require_source_match and "source_match" in skipped:
        pass

    # If env requires source_match/checksum and the rule was skipped, treat
    # the skip as a quarantine signal.
    quarantine_signals = list(skipped)
    if policy.require_checksum and "checksum" in skipped:
        quarantine_signals.append("checksum")
    if policy.require_source_match and "source_match" in skipped:
        quarantine_signals.append("source_match")

    block_rules = {"release_age", "install_scripts", "known_quarantine"}
    verdict: Verdict
    if any(r in block_rules for r in failed):
        verdict = "block"
    elif failed or any(r in {"checksum", "source_match"} for r in quarantine_signals):
        verdict = "quarantine"
    else:
        verdict = "allow"

    # log_only converts any block/quarantine into an advisory allow but keeps
    # the evidence intact for auditing.
    effective_verdict = verdict
    if policy.log_only and verdict != "allow":
        effective_verdict = "allow"
        evidence.append(f"env={policy.name}: log_only=true, downgraded {verdict} -> allow")

    logger.info(
        "policy %s@%s env=%s -> %s (failed=%s skipped=%s)",
        package,
        version,
        policy.name,
        effective_verdict,
        ",".join(failed) or "none",
        ",".join(skipped) or "none",
    )

    return PolicyDecision(
        verdict=effective_verdict,
        failed_rules=failed,
        passed_rules=passed,
        evidence=evidence,
    )
