"""Integration tests for fleet operations across two real local servers."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from mispfleet import ExecutionOptions, FailurePolicy, MispFleet, SearchQuery, ServerSelector
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.exceptions import InvalidConfigurationError, PartialFleetError
from mispfleet.models.server import ServerConfig
from tests.conftest import config_for
from tests.fake_misp import API_KEY, FakeMisp
from tests.support import contains, eq, not_contains, ok

EVENT_UUID = "9c5c1c2e-0000-4000-8000-00000000000e"


def fleet_for(servers: dict[str, ServerConfig]) -> MispFleet:
    resolver = CredentialResolver(
        {"memory": MemoryCredentialProvider(dict.fromkeys(servers, API_KEY))}
    )
    return MispFleet(servers, resolver=resolver, interactive=False)


def seed(app: FakeMisp, server_tag: str) -> None:
    app.add_event({"id": "7", "uuid": EVENT_UUID, "info": f"Campaign {server_tag}"})
    app.attributes = [
        {
            "id": "1",
            "uuid": "1f2b8a1e-0000-4000-8000-000000000001",
            "event_id": "7",
            "type": "domain",
            "value": "evil.example",
            "Event": {"uuid": EVENT_UUID, "info": f"Campaign {server_tag}"},
        },
        {"id": "2", "type": "sha256", "value": f"{server_tag}-hash"},
    ]


async def test_federated_search_preserves_provenance_and_groups(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    seed(fake_misp, "alpha")
    seed(second_fake_misp, "beta")
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:
        result = await fleet.search(SearchQuery(value="evil.example"))
    ok(result.complete)
    eq(result.total_matches, 2)
    eq({match.server for match in result.matches}, {"alpha", "beta"})
    eq(result.unique_values, 1)
    value_groups = [group for group in result.groups if group.level == "same-value-and-type"]
    eq(len(value_groups), 1)
    eq({m.server for m in value_groups[0].matches}, {"alpha", "beta"})
    for match in result.matches:
        eq(match.operation_id, result.operation_id)


async def test_partial_failure_is_data_not_silent_success(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    seed(fake_misp, "alpha")
    second_fake_misp.delay = 0.5
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "slow": config_for(second_fake_misp, name="slow", request_timeout=0.05),
    }
    async with fleet_for(servers) as fleet:
        result = await fleet.search(SearchQuery(value="evil.example"))
    ok(result.partial)
    eq(result.successful_servers, ["alpha"])
    eq(result.failed_servers, ["slow"])
    eq(result.errors["slow"].kind, "RequestTimeoutError")
    ok(result.errors["slow"].retryable)


async def test_fail_fast_policy_raises_partial_fleet_error(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    seed(fake_misp, "alpha")
    second_fake_misp.delay = 0.5
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "slow": config_for(second_fake_misp, name="slow", request_timeout=0.05),
    }
    async with fleet_for(servers) as fleet:
        with pytest.raises(PartialFleetError) as excinfo:
            await fleet.search(
                SearchQuery(value="evil.example"),
                execution=ExecutionOptions(failure_policy=FailurePolicy.FAIL_FAST),
            )
    eq(excinfo.value.failed_servers, ["slow"])


async def test_health_classifies_reachable_unauthenticated_and_down(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    servers = {
        "healthy": config_for(fake_misp, name="healthy"),
        "wrong-key": config_for(second_fake_misp, name="wrong-key"),
        "down": config_for(fake_misp, name="down", url="http://127.0.0.1:9", connect_timeout=0.5),
    }
    resolver = CredentialResolver(
        {
            "memory": MemoryCredentialProvider(
                {"healthy": API_KEY, "wrong-key": "bad-key", "down": API_KEY}
            )
        }
    )
    async with MispFleet(servers, resolver=resolver, interactive=False) as fleet:
        result = await fleet.health()
    ok(result.complete)
    healthy = result.results["healthy"]
    ok(healthy.reachable)
    ok(healthy.authenticated)
    eq(healthy.misp_version, "2.4.190")
    contains(healthy.capabilities, "sync")
    ok(healthy.latency_ms is not None)
    wrong = result.results["wrong-key"]
    ok(wrong.reachable)
    ok(not wrong.authenticated)
    eq(wrong.error.kind if wrong.error else "", "AuthenticationError")
    down = result.results["down"]
    ok(not down.reachable)
    eq(down.latency_ms, None)


async def test_health_reports_disabled_tls_verification(fake_misp: FakeMisp) -> None:
    servers = {"lab": config_for(fake_misp, name="lab", verify_tls=False)}
    async with fleet_for(servers) as fleet:
        result = await fleet.health()
    contains(result.results["lab"].warnings[0], "TLS verification")


async def test_get_event_and_selector_errors(fake_misp: FakeMisp) -> None:
    seed(fake_misp, "alpha")
    servers = {"alpha": config_for(fake_misp, name="alpha")}
    async with fleet_for(servers) as fleet:
        result = await fleet.get_event(EVENT_UUID, ServerSelector.names("alpha"))
        eq(result.results["alpha"].info, "Campaign alpha")
        with pytest.raises(InvalidConfigurationError) as unknown:
            await fleet.get_event(EVENT_UUID, ServerSelector.names("ghost"))
        contains(str(unknown.value), "ghost")
        with pytest.raises(InvalidConfigurationError) as empty:
            await fleet.get_event(EVENT_UUID, ServerSelector.group("nonexistent"))
        contains(str(empty.value), "no enabled servers")


async def test_iter_search_streams_from_all_servers(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    seed(fake_misp, "alpha")
    seed(second_fake_misp, "beta")
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:
        seen = [match async for match in fleet.iter_search(SearchQuery(), page_size=1)]
    eq(len(seen), 4)
    eq({match.server for match in seen}, {"alpha", "beta"})


async def test_fleet_from_file_resolves_env_credentials(
    fake_misp: FakeMisp, tmp_path: Path, alpha_env: None
) -> None:
    seed(fake_misp, "alpha")
    config = f"""
version: 1
servers:
  alpha:
    url: {fake_misp.url}
    credential:
      provider: env
      key: MISPFLEET_ALPHA_TEST_KEY
    allow_insecure_http: true
"""
    path = tmp_path / "fleet.yml"
    path.write_text(config, encoding="utf-8")
    async with await MispFleet.from_file(path, interactive=False) as fleet:
        result = await fleet.search(SearchQuery(value="evil.example"))
    eq(result.total_matches, 1)
    eq(result.matches[0].server, "alpha")


async def test_fleet_client_cache_reuses_instances(fake_misp: FakeMisp) -> None:
    servers = {"alpha": config_for(fake_misp, name="alpha")}
    fleet = fleet_for(servers)
    try:
        ok(fleet.client("alpha") is fleet.client("alpha"))
    finally:
        await fleet.aclose()


def test_search_result_serialization_hides_secrets(fake_misp: FakeMisp) -> None:
    servers = {"alpha": config_for(fake_misp, name="alpha")}
    dumped = str({name: config.model_dump() for name, config in servers.items()})
    not_contains(dumped, API_KEY)


@pytest.fixture
def alpha_env() -> Iterator[None]:
    os.environ["MISPFLEET_ALPHA_TEST_KEY"] = API_KEY
    yield
    del os.environ["MISPFLEET_ALPHA_TEST_KEY"]
