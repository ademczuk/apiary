"""Per-environment policy: same engine, different thresholds and behaviour.

The Apiary proxy runs at three deploy targets: ``dev`` (engineers' machines),
``preprod`` (CI / staging), and ``prod`` (production registries). Each
environment dials the policy rules to a different operating point:

* ``dev`` is permissive (audit-only, fail-open) so developers are never
  blocked by transient upstream issues.
* ``preprod`` enforces the full rule set; failures route to quarantine.
* ``prod`` is the strictest variant: tighter LLM-audit threshold and a
  longer minimum release age.

A user can override the defaults via a YAML file. The proxy chooses the
active environment from the ``APIARY_ENVIRONMENT`` env var.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

logger = logging.getLogger("apiary.policy.environments")

InstallScriptsMode = Literal["allow", "warn", "deny"]

DEFAULT_ENV_NAME = "preprod"


@dataclass
class EnvironmentPolicy:
    """Per-environment policy knobs."""

    name: str
    min_release_age_days: int
    install_scripts: InstallScriptsMode
    require_source_match: bool
    require_checksum: bool
    fail_open_on_audit_error: bool
    block_threshold: float
    log_only: bool = False


DEFAULT_ENVIRONMENTS: dict[str, EnvironmentPolicy] = {
    "dev": EnvironmentPolicy(
        name="dev",
        min_release_age_days=0,
        install_scripts="warn",
        require_source_match=False,
        require_checksum=False,
        fail_open_on_audit_error=True,
        block_threshold=0.5,
        log_only=True,
    ),
    "preprod": EnvironmentPolicy(
        name="preprod",
        min_release_age_days=7,
        install_scripts="deny",
        require_source_match=True,
        require_checksum=True,
        fail_open_on_audit_error=False,
        block_threshold=0.3,
        log_only=False,
    ),
    "prod": EnvironmentPolicy(
        name="prod",
        min_release_age_days=14,
        install_scripts="deny",
        require_source_match=True,
        require_checksum=True,
        fail_open_on_audit_error=False,
        block_threshold=0.2,
        log_only=False,
    ),
}


@dataclass
class EnvironmentRegistry:
    """Holds all configured environment policies."""

    policies: dict[str, EnvironmentPolicy] = field(
        default_factory=lambda: {k: _copy_policy(v) for k, v in DEFAULT_ENVIRONMENTS.items()}
    )

    def get(self, name: str) -> EnvironmentPolicy:
        if name not in self.policies:
            logger.warning(
                "unknown environment %r; falling back to %s", name, DEFAULT_ENV_NAME
            )
            return self.policies[DEFAULT_ENV_NAME]
        return self.policies[name]


def _copy_policy(p: EnvironmentPolicy) -> EnvironmentPolicy:
    return EnvironmentPolicy(
        name=p.name,
        min_release_age_days=p.min_release_age_days,
        install_scripts=p.install_scripts,
        require_source_match=p.require_source_match,
        require_checksum=p.require_checksum,
        fail_open_on_audit_error=p.fail_open_on_audit_error,
        block_threshold=p.block_threshold,
        log_only=p.log_only,
    )


_BOOL_TRUE = frozenset({"true", "yes", "1", "on"})
_BOOL_FALSE = frozenset({"false", "no", "0", "off"})


def _coerce_bool(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lower = value.strip().lower()
        if lower in _BOOL_TRUE:
            return True
        if lower in _BOOL_FALSE:
            return False
    return default


def _coerce_install_scripts(value: object, default: InstallScriptsMode) -> InstallScriptsMode:
    if isinstance(value, str) and value in ("allow", "warn", "deny"):
        return value  # type: ignore[return-value]
    return default


def _apply_overrides(
    base: EnvironmentPolicy, overrides: dict
) -> EnvironmentPolicy:
    """Return a new policy with any provided fields overridden."""
    return EnvironmentPolicy(
        name=base.name,
        min_release_age_days=int(overrides.get("min_release_age_days", base.min_release_age_days)),
        install_scripts=_coerce_install_scripts(
            overrides.get("install_scripts"), base.install_scripts
        ),
        require_source_match=_coerce_bool(
            overrides.get("require_source_match"), base.require_source_match
        ),
        require_checksum=_coerce_bool(
            overrides.get("require_checksum"), base.require_checksum
        ),
        fail_open_on_audit_error=_coerce_bool(
            overrides.get("fail_open_on_audit_error"), base.fail_open_on_audit_error
        ),
        block_threshold=float(overrides.get("block_threshold", base.block_threshold)),
        log_only=_coerce_bool(overrides.get("log_only"), base.log_only),
    )


def load_environment_registry(config_path: Optional[Path] = None) -> EnvironmentRegistry:
    """Build the registry from defaults, then apply YAML overrides if present.

    The YAML schema is::

        environments:
          dev:
            min_release_age_days: 0
            install_scripts: warn
            log_only: true
          preprod:
            block_threshold: 0.35
          prod:
            min_release_age_days: 21
    """
    registry = EnvironmentRegistry()
    if config_path is None or not config_path.exists():
        return registry

    try:
        import yaml
    except ImportError:
        logger.warning("pyyaml missing; environment overrides skipped")
        return registry

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("failed to read %s: %s", config_path, exc)
        return registry

    envs_section = raw.get("environments")
    if not isinstance(envs_section, dict):
        return registry

    for env_name, overrides in envs_section.items():
        if not isinstance(overrides, dict):
            continue
        base = registry.policies.get(env_name)
        if base is None:
            # Unknown environment; require a full definition.
            try:
                registry.policies[env_name] = EnvironmentPolicy(
                    name=env_name,
                    min_release_age_days=int(overrides.get("min_release_age_days", 7)),
                    install_scripts=_coerce_install_scripts(
                        overrides.get("install_scripts"), "deny"
                    ),
                    require_source_match=_coerce_bool(
                        overrides.get("require_source_match"), True
                    ),
                    require_checksum=_coerce_bool(
                        overrides.get("require_checksum"), True
                    ),
                    fail_open_on_audit_error=_coerce_bool(
                        overrides.get("fail_open_on_audit_error"), False
                    ),
                    block_threshold=float(overrides.get("block_threshold", 0.3)),
                    log_only=_coerce_bool(overrides.get("log_only"), False),
                )
            except (TypeError, ValueError) as exc:
                logger.warning("invalid environment %r: %s", env_name, exc)
            continue
        registry.policies[env_name] = _apply_overrides(base, overrides)

    return registry


def load_environment_policy(
    env_name: str, config_path: Optional[Path] = None
) -> EnvironmentPolicy:
    """Load a single environment policy, applying YAML overrides if provided."""
    return load_environment_registry(config_path).get(env_name)
