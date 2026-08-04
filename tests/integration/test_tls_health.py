"""Integration tests for TLS certificate inspection and the capability cache."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mispfleet.client import MispClient
from mispfleet.client.tlsinfo import peer_certificate_expiry
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.fleet import MispFleet
from mispfleet.models.server import ServerConfig
from mispfleet.services.health import check_server
from mispfleet.state.base import StateBackend
from mispfleet.state.memory import MemoryStateBackend
from tests.conftest import config_for
from tests.fake_misp import API_KEY, FakeMisp
from tests.support import eq, ok

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
SERVER_CERT = FIXTURES / "server-cert.pem"
SERVER_KEY = FIXTURES / "server-key.pem"


def fleet_with_state(
    servers: dict[str, ServerConfig], state: StateBackend | None = None
) -> MispFleet:
    """Build a fleet with in-memory credentials and an optional state backend."""
    resolver = CredentialResolver(
        {"memory": MemoryCredentialProvider(dict.fromkeys(servers, API_KEY))}
    )
    return MispFleet(servers, resolver=resolver, interactive=False, state=state)


@pytest.fixture
def tls_fake_misp() -> Iterator[FakeMisp]:
    """A fake MISP served over TLS with the self-signed fixture certificate."""
    app = FakeMisp(certfile=SERVER_CERT, keyfile=SERVER_KEY)
    app.start()
    yield app
    app.stop()


async def test_health_reports_certificate_expiry(tls_fake_misp: FakeMisp) -> None:
    config = config_for(tls_fake_misp, ca_bundle=SERVER_CERT)
    async with MispClient(config, api_key=API_KEY) as client:
        health = await check_server(client)
    ok(health.reachable)
    eq(health.tls_valid, True)
    ok(health.certificate_expiry is not None)
    if health.certificate_expiry is not None:
        ok(health.certificate_expiry > datetime.now(tz=UTC))


async def test_certificate_expiry_is_none_without_verification(tls_fake_misp: FakeMisp) -> None:
    unverified = config_for(tls_fake_misp, verify_tls=False)
    eq(await peer_certificate_expiry(unverified), None)


async def test_certificate_expiry_is_none_on_handshake_failure(tls_fake_misp: FakeMisp) -> None:
    untrusted = config_for(tls_fake_misp)
    eq(await peer_certificate_expiry(untrusted), None)


async def test_certificate_expiry_is_none_for_plain_http(fake_misp: FakeMisp) -> None:
    eq(await peer_certificate_expiry(config_for(fake_misp)), None)


async def test_server_capabilities_uses_cache_until_refresh(fake_misp: FakeMisp) -> None:
    backend = MemoryStateBackend()
    fleet = fleet_with_state({"alpha": config_for(fake_misp, name="alpha")}, backend)
    async with fleet:
        first = await fleet.server_capabilities("alpha")
        cached = await fleet.server_capabilities("alpha")
        eq(first.fetched_at, cached.fetched_at)
        version_calls = [seen for seen in fake_misp.requests_seen if "getVersion" in seen[1]]
        eq(len(version_calls), 1)
        refreshed = await fleet.server_capabilities("alpha", refresh=True)
        ok(refreshed.fetched_at >= first.fetched_at)
        version_calls = [seen for seen in fake_misp.requests_seen if "getVersion" in seen[1]]
        eq(len(version_calls), 2)
        eq(refreshed.misp_version, "2.4.190")
        ok("rest-search" in refreshed.capabilities)


async def test_server_capabilities_expired_cache_is_refetched(fake_misp: FakeMisp) -> None:
    backend = MemoryStateBackend()
    fleet = fleet_with_state({"alpha": config_for(fake_misp, name="alpha")}, backend)
    async with fleet:
        first = await fleet.server_capabilities("alpha", ttl_seconds=0.000001)
        stale = await backend.load_capabilities("alpha")
        ok(stale is not None and stale.expired(datetime.now(tz=UTC) + timedelta(seconds=1)))
        second = await fleet.server_capabilities("alpha")
        ok(second.fetched_at >= first.fetched_at)
        version_calls = [seen for seen in fake_misp.requests_seen if "getVersion" in seen[1]]
        eq(len(version_calls), 2)


async def test_server_capabilities_without_state_backend_probes_live(
    fake_misp: FakeMisp,
) -> None:
    fleet = fleet_with_state({"alpha": config_for(fake_misp, name="alpha")})
    async with fleet:
        await fleet.server_capabilities("alpha")
        await fleet.server_capabilities("alpha")
    version_calls = [seen for seen in fake_misp.requests_seen if "getVersion" in seen[1]]
    eq(len(version_calls), 2)
