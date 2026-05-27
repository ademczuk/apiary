"""Apiary policy engine: rules + checksum verification.

Public API:
    decide_policy(package, version, metadata, tarball_bytes=None, ...) -> PolicyDecision
    PolicyDecision
    verify_integrity(integrity_str, tarball_bytes) -> ChecksumResult
"""

from apiary_policy.checksums import (
    ChecksumResult,
    IntegrityParseError,
    compute_digest,
    parse_integrity,
    verify_integrity,
)
from apiary_policy.rules import (
    PolicyDecision,
    check_checksum,
    check_install_scripts,
    check_known_quarantine,
    check_release_age,
    check_source_match,
    decide_policy,
)

__all__ = [
    "ChecksumResult",
    "IntegrityParseError",
    "PolicyDecision",
    "check_checksum",
    "check_install_scripts",
    "check_known_quarantine",
    "check_release_age",
    "check_source_match",
    "compute_digest",
    "decide_policy",
    "parse_integrity",
    "verify_integrity",
]
