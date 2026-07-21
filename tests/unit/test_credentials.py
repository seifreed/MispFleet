"""Unit tests for credential providers; all providers run real code."""

from __future__ import annotations

import os
from uuid import uuid4

import keyring
import pytest
from keyring.backend import KeyringBackend

from mispfleet.credentials import (
    CredentialProvider,
    CredentialResolver,
    EnvironmentCredentialProvider,
    KeyringCredentialProvider,
    MemoryCredentialProvider,
    PromptCredentialProvider,
)
from mispfleet.credentials.keyring import load_keyring_module
from mispfleet.exceptions import CredentialResolutionError
from mispfleet.models.server import CredentialReference
from tests.support import contains, eq, not_contains, ok


class InMemoryKeyring(KeyringBackend):
    """A real keyring backend storing secrets in process memory."""

    priority = 1.0

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        self._store.pop((service, username), None)


def test_environment_provider_reads_and_fails_safely() -> None:
    variable = f"MISPFLEET_TEST_{uuid4().hex.upper()}"
    os.environ[variable] = "secret-value"
    try:
        eq(EnvironmentCredentialProvider().resolve(variable), "secret-value")
    finally:
        del os.environ[variable]
    with pytest.raises(CredentialResolutionError) as excinfo:
        EnvironmentCredentialProvider().resolve(variable)
    not_contains(str(excinfo.value), "secret-value")


def test_memory_provider_set_resolve_and_missing() -> None:
    provider = MemoryCredentialProvider({"a": "secret-a"})
    eq(provider.resolve("a"), "secret-a")
    provider.set("b", "secret-b")
    eq(provider.resolve("b"), "secret-b")
    with pytest.raises(CredentialResolutionError):
        provider.resolve("missing")


def test_prompt_provider_prompts_once_and_caches() -> None:
    calls: list[str] = []

    def fake_terminal(prompt: str) -> str:
        calls.append(prompt)
        return "typed-secret"

    provider = PromptCredentialProvider(input_fn=fake_terminal)
    eq(provider.resolve("research"), "typed-secret")
    eq(provider.resolve("research"), "typed-secret")
    eq(len(calls), 1)
    contains(calls[0], "research")


def test_prompt_provider_rejects_empty_input() -> None:
    provider = PromptCredentialProvider(input_fn=lambda _prompt: "")
    with pytest.raises(CredentialResolutionError):
        provider.resolve("research")


def test_prompt_provider_defaults_to_getpass() -> None:
    ok(PromptCredentialProvider()._input_fn is not None)


def test_keyring_provider_round_trip() -> None:
    original = keyring.get_keyring()
    backend = InMemoryKeyring()
    keyring.set_keyring(backend)
    try:
        backend.set_password("mispfleet", "research", "keyring-secret")
        eq(KeyringCredentialProvider().resolve("research"), "keyring-secret")
        with pytest.raises(CredentialResolutionError):
            KeyringCredentialProvider().resolve("missing-key")
    finally:
        keyring.set_keyring(original)


def test_keyring_provider_reports_missing_dependency() -> None:
    provider = KeyringCredentialProvider(module_name=f"missing_module_{uuid4().hex}")
    with pytest.raises(CredentialResolutionError) as excinfo:
        provider.resolve("any")
    contains(str(excinfo.value), "keyring")


def test_load_keyring_module_returns_real_module() -> None:
    eq(load_keyring_module("keyring"), keyring)


def test_resolver_dispatches_and_rejects_unknown_provider() -> None:
    providers: dict[str, CredentialProvider] = {
        "memory": MemoryCredentialProvider({"prod": "secret"})
    }
    resolver = CredentialResolver(providers)
    eq(resolver.resolve(CredentialReference(provider="memory", key="prod")), "secret")
    with pytest.raises(CredentialResolutionError):
        resolver.resolve(CredentialReference(provider="env", key="prod"))


def test_default_resolver_registers_all_mvp_providers() -> None:
    from mispfleet.credentials.base import default_resolver

    interactive = default_resolver()
    eq(sorted(interactive._providers), ["env", "keyring", "memory", "prompt"])
    memory = MemoryCredentialProvider({"prod": "secret"})
    non_interactive = default_resolver(memory=memory, interactive=False)
    eq(sorted(non_interactive._providers), ["env", "keyring", "memory"])
    eq(non_interactive.resolve(CredentialReference(provider="memory", key="prod")), "secret")
