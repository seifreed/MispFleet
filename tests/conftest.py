"""Shared fixtures: every test talks to a real local HTTP server."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from pydantic import AnyHttpUrl

from mispfleet.models.server import CredentialReference, RetryConfig, ServerConfig
from tests.fake_misp import FakeMisp


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
