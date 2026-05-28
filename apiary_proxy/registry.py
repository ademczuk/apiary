"""Registry abstraction for the Apiary proxy.

The original Apiary proxy hard-coded npm registry semantics. v2 splits the
upstream wiring into a small abstract interface so the same policy engine
can gate PyPI and Composer (Packagist) traffic in parallel.

Every concrete registry implementation returns a ``PackageMetadata``
dataclass with the seven fields the policy rules need:

- ``name`` / ``version``: canonical identifiers, ecosystem-normalized
- ``ecosystem``: "npm" | "pypi" | "composer"
- ``release_time``: ISO-8601 publish timestamp, or None when the registry
  does not surface one
- ``install_scripts``: lifecycle-hook name -> shell command. Each
  ecosystem has its own hook vocabulary; the policy engine treats every
  entry as a candidate for the lifecycle-script rule
- ``integrity_hash``: digest of the distribution archive in the algo's
  native lowercase hex form (or empty SRI for npm)
- ``integrity_algo``: "sha512" (npm) | "sha256" (PyPI) | "sha1" (Composer)
- ``repository_url``: canonical source-repo URL when published, None
  otherwise (PyPI ships this less consistently than npm and Composer)
- ``tarball_url``: upstream download URL for the dist archive

The proxy translates an incoming HTTP request into ``(package, version)``,
hands the pair to the Registry implementation, and the implementation
abstracts the wire protocol of the underlying index.

The Registry interface is deliberately tiny. Anything ecosystem-specific
that the proxy needs (route shape, filename conventions, archive media
type) stays inside the implementation; the policy engine never sees it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PackageMetadata:
    """Ecosystem-agnostic package metadata.

    The policy engine reads only this shape. Each concrete Registry maps
    its native metadata format onto these fields before the policy rules
    run.
    """

    name: str
    version: str
    ecosystem: str  # "npm" | "pypi" | "composer"
    release_time: str | None  # ISO-8601 datetime or None when missing
    install_scripts: dict[str, str] = field(default_factory=dict)
    integrity_hash: str | None = None  # SRI for npm, lowercase hex otherwise
    integrity_algo: str = "sha512"  # "sha512" | "sha256" | "sha1"
    repository_url: str | None = None
    tarball_url: str = ""
    # Native metadata blob preserved for ecosystem-specific rule extensions
    # (the proxy never inspects this; it is opaque to the policy engine).
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for audit-log writes and JSON responses."""
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "release_time": self.release_time,
            "install_scripts": dict(self.install_scripts),
            "integrity_hash": self.integrity_hash,
            "integrity_algo": self.integrity_algo,
            "repository_url": self.repository_url,
            "tarball_url": self.tarball_url,
        }


class RegistryError(Exception):
    """Generic registry failure. Concrete subclasses signal cause."""


class PackageNotFoundError(RegistryError):
    """Raised when the upstream returns 404 for a package or version."""


class UpstreamError(RegistryError):
    """Raised when upstream returns 5xx, malformed JSON, or a timeout."""


class Registry(ABC):
    """Ecosystem-agnostic upstream registry interface.

    Implementations:
        ``apiary_proxy.npm_registry.NpmRegistry``
        ``apiary_proxy.pypi_registry.PyPIRegistry``
        ``apiary_proxy.composer_registry.ComposerRegistry``
    """

    ecosystem: str = "unknown"

    @abstractmethod
    async def get_metadata(self, package: str, version: str) -> PackageMetadata:
        """Fetch and normalize metadata for ``package@version``."""

    @abstractmethod
    async def get_tarball(self, package: str, version: str) -> bytes:
        """Download the distribution archive bytes for ``package@version``."""

    @abstractmethod
    def upstream_url(self) -> str:
        """Return the configured upstream root URL."""

    @abstractmethod
    def normalize_package_name(self, name: str) -> str:
        """Canonicalize a package name per ecosystem rules.

        - npm: case-preserving; scoped names keep the leading ``@``
        - PyPI (PEP 503): lowercase, runs of ``[-_.]`` collapse to ``-``
        - Composer: case-preserving; ``vendor/package`` stays as written
        """


def metadata_to_npm_shape(meta: PackageMetadata) -> dict[str, Any]:
    """Project a PackageMetadata back onto an npm-style versions block.

    The five rules in ``apiary_policy.rules`` were written against the npm
    metadata shape (``versions[ver].scripts``, ``time[ver]``,
    ``versions[ver].dist.integrity``, ``versions[ver].repository.url``).
    Wrapping a PackageMetadata in this projection lets the same rule code
    fire against PyPI and Composer packages without duplicating logic.

    Integrity strings are emitted in SRI form (``algo-base64``) when the
    algo is sha512/sha384/sha256 so ``apiary_policy.checksums`` can parse
    them with no extra branch. Composer's sha1 is emitted as a hex-flag
    SRI extension that the checksum verifier understands as a hex hash.
    """
    import base64

    integrity_field: str | None = None
    if meta.integrity_hash:
        algo = meta.integrity_algo
        if algo in ("sha512", "sha384", "sha256"):
            try:
                raw = bytes.fromhex(meta.integrity_hash)
                integrity_field = f"{algo}-" + base64.b64encode(raw).decode("ascii")
            except ValueError:
                # The npm registry already publishes integrity in SRI base64
                # form. Preserve the string as-is rather than corrupting it.
                integrity_field = meta.integrity_hash
        else:
            # Composer ships sha1 hex; the checksum verifier handles it
            # through the hex-prefixed form ``algo-hex:<hex>``.
            integrity_field = f"{algo}-hex:{meta.integrity_hash}"

    version_block: dict[str, Any] = {
        "name": meta.name,
        "version": meta.version,
        "scripts": dict(meta.install_scripts),
        "dist": {
            "tarball": meta.tarball_url,
            "integrity": integrity_field,
        },
    }
    if meta.repository_url:
        version_block["repository"] = {"url": meta.repository_url}

    npm_shape: dict[str, Any] = {
        "name": meta.name,
        "time": {meta.version: meta.release_time} if meta.release_time else {},
        "versions": {meta.version: version_block},
        "_ecosystem": meta.ecosystem,
    }
    return npm_shape


__all__ = [
    "PackageMetadata",
    "Registry",
    "RegistryError",
    "PackageNotFoundError",
    "UpstreamError",
    "metadata_to_npm_shape",
]
