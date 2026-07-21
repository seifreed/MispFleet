"""Credential provider abstraction."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mispfleet.exceptions import CredentialResolutionError
from mispfleet.models.server import CredentialReference


@runtime_checkable
class CredentialProvider(Protocol):
    """Resolves a credential key to its secret value."""

    def resolve(self, key: str) -> str:
        """Return the secret for ``key`` or raise ``CredentialResolutionError``."""
        ...


class CredentialResolver:
    """Dispatches credential references to their configured providers."""

    def __init__(self, providers: dict[str, CredentialProvider]) -> None:
        self._providers = providers

    def resolve(self, reference: CredentialReference) -> str:
        """Resolve a credential reference without ever logging the secret."""
        provider = self._providers.get(reference.provider)
        if provider is None:
            raise CredentialResolutionError(
                f"no credential provider registered for {reference.provider!r}"
            )
        return provider.resolve(reference.key)
