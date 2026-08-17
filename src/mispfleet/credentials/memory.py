"""In-memory credential provider for direct injection through the Python API."""

from __future__ import annotations

from mispfleet.exceptions import CredentialResolutionError


class MemoryCredentialProvider:
    """Holds secrets injected programmatically; nothing is ever persisted."""

    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets = dict(secrets or {})

    def set(self, key: str, value: str) -> None:
        """Register a secret under ``key``."""
        self._secrets[key] = value

    def resolve(self, key: str) -> str:
        """Return the secret registered under ``key``."""
        value = self._secrets.get(key)
        if not value:
            raise CredentialResolutionError(f"no in-memory credential registered for {key!r}")
        return value
