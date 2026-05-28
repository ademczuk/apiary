"""Apiary registry proxy with policy gating.

The original proxy was npm-only. v2 adds a Registry abstraction with
parallel adapters for PyPI and Composer so the same policy engine can
gate three ecosystems from one binary.

Public API:
    ProxyConfig, ProxyState, app, main             # FastAPI plumbing
    Registry, PackageMetadata                      # ecosystem-agnostic interface
    NpmRegistry, PyPIRegistry, ComposerRegistry    # concrete adapters
    metadata_to_npm_shape                          # bridge to policy rules
"""

from apiary_proxy.composer_registry import ComposerRegistry
from apiary_proxy.npm_registry import NpmRegistry
from apiary_proxy.proxy import ProxyConfig, ProxyState, app, main
from apiary_proxy.pypi_registry import PyPIRegistry
from apiary_proxy.registry import (
    PackageMetadata,
    PackageNotFoundError,
    Registry,
    RegistryError,
    UpstreamError,
    metadata_to_npm_shape,
)

__all__ = [
    "ComposerRegistry",
    "NpmRegistry",
    "PackageMetadata",
    "PackageNotFoundError",
    "ProxyConfig",
    "ProxyState",
    "PyPIRegistry",
    "Registry",
    "RegistryError",
    "UpstreamError",
    "app",
    "main",
    "metadata_to_npm_shape",
]
