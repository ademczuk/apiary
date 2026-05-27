"""Subresource-integrity-style checksum verification for npm tarballs.

npm dist.integrity uses the SRI format: ``<algo>-<base64-digest>``. The npm
registry currently emits sha512; older metadata may carry sha384 or sha256.
This module parses the SRI string, computes the same digest over the tarball
bytes, and reports both expected and actual digests so callers can decide
how to surface a mismatch.

Public surface:
    parse_integrity(integrity_str) -> (algo, expected_b64)
    compute_digest(tarball_bytes, algo) -> actual_b64
    verify_integrity(integrity_str, tarball_bytes) -> ChecksumResult
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Literal

SupportedAlgo = Literal["sha512", "sha384", "sha256"]

_ALGO_TO_HASHLIB = {
    "sha512": hashlib.sha512,
    "sha384": hashlib.sha384,
    "sha256": hashlib.sha256,
}


@dataclass(frozen=True)
class ChecksumResult:
    """Outcome of comparing a tarball against its declared integrity field."""

    algo: SupportedAlgo
    expected_b64: str
    actual_b64: str
    matches: bool
    error: str | None = None


class IntegrityParseError(ValueError):
    """Raised when an SRI string cannot be split into algo + digest."""


def parse_integrity(integrity_str: str) -> tuple[SupportedAlgo, str]:
    """Split an SRI integrity string into ``(algo, expected_b64)``.

    SRI permits whitespace-separated alternatives such as
    ``sha512-AAA== sha384-BBB==``. We pick the strongest supported algo
    available because that is what npm prefers at install time.
    """
    if not integrity_str or not isinstance(integrity_str, str):
        raise IntegrityParseError("integrity is empty or not a string")

    alternatives = integrity_str.strip().split()
    parsed: list[tuple[SupportedAlgo, str]] = []
    for alt in alternatives:
        if "-" not in alt:
            continue
        algo, _, digest = alt.partition("-")
        algo_lower = algo.strip().lower()
        if algo_lower in _ALGO_TO_HASHLIB and digest:
            parsed.append((algo_lower, digest.strip()))

    if not parsed:
        raise IntegrityParseError(
            f"no supported algorithm in integrity string: {integrity_str!r}"
        )

    # Strength ordering: prefer sha512, then sha384, then sha256.
    ranking = {"sha512": 3, "sha384": 2, "sha256": 1}
    parsed.sort(key=lambda item: ranking[item[0]], reverse=True)
    return parsed[0]


def compute_digest(tarball_bytes: bytes, algo: SupportedAlgo) -> str:
    """Return the base64-encoded digest of ``tarball_bytes`` under ``algo``."""
    if algo not in _ALGO_TO_HASHLIB:
        raise ValueError(f"unsupported algo: {algo}")
    raw = _ALGO_TO_HASHLIB[algo](tarball_bytes).digest()
    return base64.b64encode(raw).decode("ascii")


def verify_integrity(integrity_str: str, tarball_bytes: bytes) -> ChecksumResult:
    """Parse the SRI string and check it against the tarball bytes.

    Returns a populated ``ChecksumResult`` even when the integrity string is
    malformed; callers can branch on ``result.error`` for parsing failures
    versus ``result.matches`` for a clean comparison.
    """
    try:
        algo, expected_b64 = parse_integrity(integrity_str)
    except IntegrityParseError as exc:
        return ChecksumResult(
            algo="sha512",
            expected_b64="",
            actual_b64="",
            matches=False,
            error=str(exc),
        )

    if not isinstance(tarball_bytes, (bytes, bytearray)):
        return ChecksumResult(
            algo=algo,
            expected_b64=expected_b64,
            actual_b64="",
            matches=False,
            error="tarball_bytes is not bytes-like",
        )

    actual_b64 = compute_digest(bytes(tarball_bytes), algo)
    expected_norm = expected_b64.strip().rstrip("=")
    actual_norm = actual_b64.strip().rstrip("=")
    return ChecksumResult(
        algo=algo,
        expected_b64=expected_b64,
        actual_b64=actual_b64,
        matches=expected_norm == actual_norm,
        error=None,
    )


def hex_digest(tarball_bytes: bytes, algo: SupportedAlgo = "sha512") -> str:
    """Convenience helper returning a hex digest for human-facing reports."""
    if algo not in _ALGO_TO_HASHLIB:
        raise ValueError(f"unsupported algo: {algo}")
    return _ALGO_TO_HASHLIB[algo](tarball_bytes).hexdigest()
