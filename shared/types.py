"""Apiary shared types - mirrors ModuleWarden v1 vocabulary.

ModuleWarden defines the canonical types in TypeScript at
packages/shared/src/types.ts. This module mirrors them in Python so
apiary can use the same vocabulary in audit memos, decision records,
and downstream Prisma migration when we port to ModuleWarden's stack
post-hackathon.

Adopted concepts:
- Verdict: allow / block / quarantine
- PackageIdentity: name, version, registry, tarball hash
- AuditContext: package + predecessor + trigger
- Decision: full verdict envelope with provenance
- Override: admin override semantics (placeholder, not yet wired)
- ThreatClass: A/B/C taxonomy from ModuleWarden architecture doc
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Verdict = Literal["allow", "block", "quarantine"]
ThreatClass = Literal["A", "B", "C"]
TriggerKind = Literal["preflight", "subscription", "manual", "re-audit"]
ActorType = Literal["agent", "admin"]


@dataclass
class PackageIdentity:
    """Mirrors ModuleWarden's PackageIdentity."""

    name: str
    version: str
    registry_source: str = "registry.npmjs.org"
    tarball_hash: str = ""


@dataclass
class AuditContext:
    """Mirrors ModuleWarden's AuditContext."""

    package_identity: PackageIdentity
    predecessor_version: str | None = None
    predecessor_hash: str | None = None
    trigger: TriggerKind = "preflight"
    threat_class: ThreatClass = "A"


@dataclass
class Decision:
    """Mirrors ModuleWarden's Decision envelope."""

    verdict: Verdict
    reason_summary: str
    predecessor_version: str | None = None
    predecessor_hash: str | None = None
    prompt_versions: list[str] = field(default_factory=list)
    model_profile: str = "default"
    scores: dict[str, float] = field(default_factory=dict)
    evidence_references: list[str] = field(default_factory=list)
    pi_session_id: str | None = None
    pi_run_id: str | None = None
    actor_type: ActorType = "agent"
    threat_class: ThreatClass = "A"


@dataclass
class Override:
    """Admin-level override of a verdict.

    Placeholder; not yet wired into apiary. Documented here so the
    vocabulary is available when we port the admin console post-event.
    """

    admin_identity: str
    scope: str
    reason: str
    timestamp: str
    supersedes_decision_id: str


THREAT_CLASS_DESCRIPTIONS: dict[ThreatClass, str] = {
    "A": "Compromised-Maintainer Version Bump (primary apiary focus)",
    "B": (
        "Supply-Chain Malware (typosquatting, dependency confusion) "
        "- apiary does NOT optimize for this class"
    ),
    "C": (
        "Novel Vulnerability Discovery - apiary uses pattern checks "
        "but is NOT a general novel-vulnerability oracle"
    ),
}
