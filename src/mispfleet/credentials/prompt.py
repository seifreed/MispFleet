"""Interactive prompt credential provider."""

from __future__ import annotations

import getpass
from collections.abc import Callable

from mispfleet.exceptions import CredentialResolutionError


class PromptCredentialProvider:
    """Prompts the user for a secret; never persists what was entered."""

    def __init__(self, input_fn: Callable[[str], str] | None = None) -> None:
        self._input_fn = input_fn or getpass.getpass
        self._cache: dict[str, str] = {}

    def resolve(self, key: str) -> str:
        """Prompt once per key and keep the value only in process memory."""
        if key in self._cache:
            return self._cache[key]
        value = self._input_fn(f"API key for {key}: ")
        if not value:
            raise CredentialResolutionError(f"empty credential entered for {key!r}")
        self._cache[key] = value
        return value
