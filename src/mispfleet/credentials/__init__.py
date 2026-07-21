"""Credential resolution: references in configuration, secrets only in memory."""

from mispfleet.credentials.base import CredentialProvider, CredentialResolver
from mispfleet.credentials.environment import EnvironmentCredentialProvider
from mispfleet.credentials.keyring import KeyringCredentialProvider
from mispfleet.credentials.memory import MemoryCredentialProvider
from mispfleet.credentials.prompt import PromptCredentialProvider

__all__ = [
    "CredentialProvider",
    "CredentialResolver",
    "EnvironmentCredentialProvider",
    "KeyringCredentialProvider",
    "MemoryCredentialProvider",
    "PromptCredentialProvider",
]
