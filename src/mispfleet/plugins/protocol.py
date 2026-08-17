"""Typed plugin contract."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel


class PluginCategory(StrEnum):
    """Extension points a plugin may provide."""

    CREDENTIAL_PROVIDER = "credential-provider"
    POLICY = "policy"
    TRANSFORMER = "transformer"
    VALIDATOR = "validator"
    EXPORTER = "exporter"
    STATE_BACKEND = "state-backend"
    CONFLICT_RESOLVER = "conflict-resolver"
    ENRICHMENT_PROVIDER = "enrichment-provider"


class PluginInfo(BaseModel):
    """Metadata a plugin must declare."""

    name: str
    version: str
    category: PluginCategory
    compatible_with: str


@runtime_checkable
class MispFleetPlugin(Protocol):
    """Contract every plugin implementation must satisfy.

    Plugins are never auto-activated merely because a package is installed;
    activation is always an explicit call.
    """

    def info(self) -> PluginInfo:
        """Describe the plugin."""
        ...

    def activate(self) -> Any:
        """Return the extension object (provider, policy, exporter, ...)."""
        ...
