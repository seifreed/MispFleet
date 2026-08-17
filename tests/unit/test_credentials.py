"""Unit tests for credential providers; all providers run real code."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
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
    OnePasswordCredentialProvider,
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


class LockedKeyring(KeyringBackend):
    """A real backend behaving like a locked keychain or a headless host."""

    priority = 1.0

    def __init__(self, reason: str = "the keychain is locked") -> None:
        self.reason = reason

    def get_password(self, service: str, username: str) -> str | None:
        raise keyring.errors.KeyringLocked(self.reason)

    def set_password(self, service: str, username: str, password: str) -> None:
        raise keyring.errors.KeyringLocked(self.reason)

    def delete_password(self, service: str, username: str) -> None:
        raise keyring.errors.KeyringLocked(self.reason)


def test_keyring_backend_failure_surfaces_as_a_typed_error() -> None:
    """A locked keychain raised a backend exception straight through resolve()."""
    original = keyring.get_keyring()
    keyring.set_keyring(LockedKeyring())
    try:
        with pytest.raises(CredentialResolutionError) as excinfo:
            KeyringCredentialProvider().resolve("research")
        contains(str(excinfo.value), "KeyringLocked")
    finally:
        keyring.set_keyring(original)


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
    eq(sorted(interactive._providers), ["env", "keyring", "memory", "op", "prompt"])
    memory = MemoryCredentialProvider({"prod": "secret"})
    non_interactive = default_resolver(memory=memory, interactive=False)
    eq(sorted(non_interactive._providers), ["env", "keyring", "memory", "op"])
    eq(non_interactive.resolve(CredentialReference(provider="memory", key="prod")), "secret")


FAKE_OP = """#!/bin/sh
if [ "$1" != "read" ]; then
  exit 64
fi
case "$2" in
  op://lab/misp/apikey)
    printf 'the-op-secret'
    ;;
  op://lab/empty/field)
    printf ''
    ;;
  op://lab/binary/field)
    printf '\\377\\376not utf-8'
    ;;
  *)
    exit 1
    ;;
esac
"""


@pytest.fixture
def fake_op(tmp_path: Path) -> Iterator[None]:
    if os.name == "nt":
        pytest.skip("the op CLI fake is a POSIX shell script")
    executable = tmp_path / "op"
    executable.write_text(FAKE_OP, encoding="utf-8")
    executable.chmod(0o700)
    original = os.environ["PATH"]
    os.environ["PATH"] = f"{tmp_path}{os.pathsep}{original}"
    yield
    os.environ["PATH"] = original


def test_onepassword_provider_resolves_through_real_cli(fake_op: None) -> None:
    provider = OnePasswordCredentialProvider()
    eq(provider.resolve("op://lab/misp/apikey"), "the-op-secret")


def test_onepassword_provider_failures_never_leak_the_secret(fake_op: None) -> None:
    provider = OnePasswordCredentialProvider()
    with pytest.raises(CredentialResolutionError) as bad_prefix:
        provider.resolve("lab/misp/apikey")
    contains(str(bad_prefix.value), "op://")
    with pytest.raises(CredentialResolutionError) as unknown:
        provider.resolve("op://lab/missing/field")
    contains(str(unknown.value), "op://lab/missing/field")
    not_contains(str(unknown.value), "the-op-secret")
    with pytest.raises(CredentialResolutionError) as empty:
        provider.resolve("op://lab/empty/field")
    contains(str(empty.value), "no value")


def test_onepassword_provider_rejects_non_utf8_output(fake_op: None) -> None:
    """A CLI emitting raw bytes leaked UnicodeDecodeError to the caller."""
    provider = OnePasswordCredentialProvider()
    with pytest.raises(CredentialResolutionError) as excinfo:
        provider.resolve("op://lab/binary/field")
    contains(str(excinfo.value), "non-UTF-8")


def test_onepassword_provider_requires_the_cli_on_path() -> None:
    provider = OnePasswordCredentialProvider(executable="op-definitely-absent")
    with pytest.raises(CredentialResolutionError) as missing:
        provider.resolve("op://lab/misp/apikey")
    contains(str(missing.value), "not found on PATH")


def test_prompt_provider_reports_unreadable_input() -> None:
    """getpass raises EOFError on closed or exhausted stdin."""

    def closed_terminal(prompt: str) -> str:
        raise EOFError("stdin is closed")

    provider = PromptCredentialProvider(input_fn=closed_terminal)
    with pytest.raises(CredentialResolutionError) as excinfo:
        provider.resolve("research")
    contains(str(excinfo.value), "no input available")


def test_onepassword_provider_types_a_spawn_failure(tmp_path: Path) -> None:
    """`which` finds it, then the exec fails: the raw OSError must be typed.

    A file with an invalid executable format is found on PATH but cannot be
    started; the provider contract promises a CredentialResolutionError.
    """
    if os.name == "nt":
        pytest.skip("an exec-format failure is a POSIX behaviour")
    executable = tmp_path / "op"
    executable.write_bytes(b"\xff\xfe not a program")
    executable.chmod(0o700)
    original = os.environ["PATH"]
    os.environ["PATH"] = f"{tmp_path}{os.pathsep}{original}"
    try:
        with pytest.raises(CredentialResolutionError) as excinfo:
            OnePasswordCredentialProvider().resolve("op://lab/misp/apikey")
        contains(str(excinfo.value), "could not be started")
    finally:
        os.environ["PATH"] = original
