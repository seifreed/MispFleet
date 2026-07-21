"""OS keyring credential provider (optional ``keyring`` extra)."""

from __future__ import annotations

import importlib
from types import ModuleType

from mispfleet.exceptions import CredentialResolutionError

SERVICE_NAME = "mispfleet"


def load_keyring_module(module_name: str = "keyring") -> ModuleType:
    """Import the keyring backend module, translating a missing dependency."""
    try:
        return importlib.import_module(module_name)
    except ImportError as error:
        raise CredentialResolutionError(
            "the OS keyring provider requires the 'keyring' extra: "
            "pip install 'mispfleet[keyring]'"
        ) from error


class KeyringCredentialProvider:
    """Resolves credentials from the operating-system keyring."""

    def __init__(self, service: str = SERVICE_NAME, module_name: str = "keyring") -> None:
        self._service = service
        self._module_name = module_name

    def resolve(self, key: str) -> str:
        """Return the secret stored in the OS keyring under ``key``."""
        backend = load_keyring_module(self._module_name)
        value = backend.get_password(self._service, key)
        if not value:
            raise CredentialResolutionError(
                f"no keyring entry for service {self._service!r} and key {key!r}"
            )
        return str(value)
