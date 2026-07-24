"""Shared fixtures: every test talks to real local servers."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from pydantic import AnyHttpUrl

from mispfleet.models.server import CredentialReference, RetryConfig, ServerConfig
from tests.fake_misp import FakeMisp
from tests.mariadb_server import EphemeralMariaDB


@pytest.fixture(scope="session")
def mariadb_dsn() -> Iterator[str]:
    """DSN of a real MariaDB server: external via env var, or ephemeral."""
    override = os.environ.get("MISPFLEET_TEST_MARIADB_DSN")
    if override:
        yield override
        return
    server = EphemeralMariaDB()
    server.start()
    yield server.dsn
    server.stop()


@pytest.fixture
def fake_misp() -> Iterator[FakeMisp]:
    """A running fake MISP server, stopped after the test."""
    app = FakeMisp()
    app.start()
    yield app
    app.stop()


@pytest.fixture
def second_fake_misp() -> Iterator[FakeMisp]:
    """A second independent fake MISP server for multiserver scenarios."""
    app = FakeMisp()
    app.start()
    yield app
    app.stop()


def config_for(
    app: FakeMisp,
    name: str = "test-server",
    **overrides: object,
) -> ServerConfig:
    """Build a ServerConfig pointing at a fake MISP instance."""
    fields: dict[str, object] = {
        "name": name,
        "url": AnyHttpUrl(app.url),
        "credential": CredentialReference(provider="memory", key=name),
        "allow_insecure_http": True,
        "request_timeout": 5.0,
        "connect_timeout": 5.0,
        "retry": RetryConfig(max_attempts=1, initial_delay=0.0, jitter=False),
    }
    fields.update(overrides)
    return ServerConfig.model_validate(fields)
