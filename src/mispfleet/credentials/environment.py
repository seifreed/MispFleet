"""Environment-variable credential provider."""

from __future__ import annotations

import os

from mispfleet.exceptions import CredentialResolutionError


class EnvironmentCredentialProvider:
    """Resolves credentials from user-defined environment variables."""

    def resolve(self, key: str) -> str:
        """Return the value of the environment variable named ``key``."""
        value = os.environ.get(key)
        if not value:
            raise CredentialResolutionError(f"environment variable {key!r} is not set or empty")
        return value
