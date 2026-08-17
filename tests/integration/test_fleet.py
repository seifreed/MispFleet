"""Integration tests for fleet operations across two real local servers."""

from __future__ import annotations

import asyncio
import os
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from mispfleet import ExecutionOptions, FailurePolicy, MispFleet, SearchQuery, ServerSelector
from mispfleet.client import MispClient
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.exceptions import (
    ConnectionFailedError,
    InvalidConfigurationError,
    PartialFleetError,
)
from mispfleet.models.server import CredentialReference, ServerConfig
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


def divergent_libraries(alpha: FakeMisp, beta: FakeMisp) -> None:
    alpha.version_payload = {"version": "2.4.190", "perm_sync": True}
    beta.version_payload = {"version": "2.4.199", "perm_sync": True}
    alpha.taxonomies = [{"id": "1", "namespace": "tlp", "enabled": True, "version": "9"}, {}]
    beta.taxonomies = [{"id": "1", "namespace": "tlp", "enabled": True, "version": "7"}]
    alpha.warninglists = [{"id": "1", "name": "rfc5735", "enabled": True, "version": "3"}, {}]
    beta.warninglists = [{"id": "1", "name": "rfc5735", "enabled": False, "version": "3"}]
    alpha.feeds = [{"id": "1", "name": "osint", "url": "https://feed.example", "enabled": True}, {}]
    alpha.galaxies = [{"id": "1", "name": "Threat Actor", "version": "5"}, {}]
    beta.galaxies = [{"id": "1", "name": "Threat Actor", "version": "5"}]
    alpha.templates = [{"name": "file", "version": "11"}, {}]
    beta.templates = [{"name": "file", "version": "10"}]


async def test_fleet_audit_reports_drift(fake_misp: FakeMisp, second_fake_misp: FakeMisp) -> None:
    divergent_libraries(fake_misp, second_fake_misp)
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:
        result = await fleet.audit()
    ok(result.complete)
    ok(not result.consistent)
    by_key = {(f.dimension, f.key): f for f in result.findings}
    eq(by_key[("taxonomies", "tlp")].kind, "mismatch")
    eq(by_key[("taxonomies", "tlp")].values, {"alpha": "on v9", "beta": "on v7"})
    eq(by_key[("warninglists", "rfc5735")].kind, "mismatch")
    eq(by_key[("feeds", "osint")].kind, "missing")
    eq(by_key[("feeds", "osint")].values["beta"], None)
    eq(by_key[("misp", "version")].values, {"alpha": "2.4.190", "beta": "2.4.199"})
    eq(by_key[("templates", "file")].kind, "mismatch")
    ok(("galaxies", "Threat Actor") not in by_key)


async def test_fleet_audit_consistent_and_single_server(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    for app in (fake_misp, second_fake_misp):
        app.taxonomies = [{"id": "1", "namespace": "tlp", "enabled": True, "version": "9"}]
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:
        result = await fleet.audit()
    ok(result.consistent)
    solo = {"alpha": config_for(fake_misp, name="alpha")}
    async with fleet_for(solo) as fleet:
        single = await fleet.audit()
    ok(single.consistent)


async def test_federated_sightings_preserve_provenance(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    for app, tag in ((fake_misp, "alpha"), (second_fake_misp, "beta")):
        app.attributes = [
            {
                "id": "1",
                "uuid": f"aa000000-0000-4000-8000-00000000000{1 if tag == 'alpha' else 2}",
                "event_id": "7",
                "type": "domain",
                "value": "evil.example",
            },
            {
                "id": "2",
                "uuid": "bb000000-0000-4000-8000-000000000009",
                "event_id": "7",
                "type": "domain",
                "value": "other.example",
            },
        ]
        app.sightings = [
            {
                "id": "1",
                "uuid": f"cc000000-0000-4000-8000-00000000000{1 if tag == 'alpha' else 2}",
                "attribute_uuid": app.attributes[0]["uuid"],
                "event_id": "7",
                "type": "0",
                "date_sighting": "1754500000",
            },
            {
                "id": "2",
                "attribute_uuid": "bb000000-0000-4000-8000-000000000009",
                "event_id": "7",
                "type": "0",
            },
        ]
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:
        result = await fleet.sightings("evil.example")
    ok(result.complete)
    eq(result.total_sightings, 2)
    eq({record.server for record in result.sightings}, {"alpha", "beta"})
    for record in result.sightings:
        eq(record.value, "evil.example")
        eq(record.event_id, "7")
        eq(record.operation_id, result.operation_id)
        ok(record.attribute_uuid != "bb000000-0000-4000-8000-000000000009")
    async with fleet_for(servers) as fleet:
        empty = await fleet.sightings("absent.example")
    eq(empty.total_sightings, 0)


async def test_federated_sightings_partial_on_down_server(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.attributes = [
        {
            "id": "1",
            "uuid": "aa000000-0000-4000-8000-000000000001",
            "event_id": "7",
            "type": "domain",
            "value": "evil.example",
        },
    ]
    fake_misp.sightings = [
        {
            "id": "1",
            "attribute_uuid": "aa000000-0000-4000-8000-000000000001",
            "event_id": "7",
            "type": "0",
        },
    ]
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    second_fake_misp.stop()
    async with fleet_for(servers) as fleet:
        result = await fleet.sightings("evil.example")
    ok(result.partial)
    eq(result.failed_servers, ["beta"])
    eq(result.total_sightings, 1)


async def test_search_groups_shared_indicators_and_possible_matches(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    shared = [
        {
            "id": "1",
            "event_id": "7",
            "type": "domain",
            "value": "one.example",
            "Event": {"uuid": "11111111-0000-4000-8000-000000000001", "info": "Campaign Q3"},
        },
        {
            "id": "2",
            "event_id": "7",
            "type": "domain",
            "value": "two.example",
            "Event": {"uuid": "11111111-0000-4000-8000-000000000001", "info": "Campaign Q3"},
        },
    ]
    fake_misp.attributes = shared
    second_fake_misp.attributes = [
        {
            **item,
            "Event": {"uuid": "22222222-0000-4000-8000-000000000002", "info": "Campaign Q3 copy"},
        }
        for item in shared
    ]
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:
        result = await fleet.search(SearchQuery())
    shared_groups = [g for g in result.groups if g.level == "shared-indicators"]
    eq(len(shared_groups), 1)
    eq({m.server for m in shared_groups[0].matches}, {"alpha", "beta"})


async def test_search_groups_possible_match_without_hard_overlap(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.attributes = [
        {
            "id": "1",
            "event_id": "7",
            "type": "domain",
            "value": "one.example",
            "Tag": [{"name": "tlp:green"}],
            "Event": {"uuid": "11111111-0000-4000-8000-000000000001", "info": "Emotet wave March"},
        },
    ]
    second_fake_misp.attributes = [
        {
            "id": "1",
            "event_id": "9",
            "type": "domain",
            "value": "one.example",
            "Tag": [{"name": "tlp:green"}],
            "Event": {"uuid": "22222222-0000-4000-8000-000000000002", "info": "Emotet wave March"},
        },
    ]
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:
        result = await fleet.search(SearchQuery())
    possible = [g for g in result.groups if g.level == "possible-match"]
    eq(len(possible), 1)
    eq(len(possible[0].matches), 2)
    ok(not [g for g in result.groups if g.level == "shared-indicators"])


async def test_update_libraries_across_fleet(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:
        result = await fleet.update_libraries()
    ok(result.complete)
    for name in ("alpha", "beta"):
        eq(
            sorted(result.results[name]),
            ["galaxies", "noticelists", "taxonomies", "warninglists"],
        )
        contains(result.results[name]["taxonomies"], "updated")


async def test_set_warninglist_and_taxonomy_across_fleet(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.warninglists = [
        {"id": "7", "name": "other-list", "enabled": True},
        {"id": "1", "name": "rfc5735", "enabled": False},
    ]
    second_fake_misp.warninglists = [{"id": "9", "name": "rfc5735", "enabled": False}]
    fake_misp.taxonomies = [
        {"id": "5", "namespace": "pap", "enabled": True},
        {"id": "1", "namespace": "tlp", "enabled": False},
    ]
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:
        toggled = await fleet.set_warninglist("rfc5735", True)
        ok(toggled.complete)
        ok(fake_misp.warninglists[1]["enabled"])
        ok(second_fake_misp.warninglists[0]["enabled"])
        reverted = await fleet.set_warninglist("rfc5735", False)
        ok(reverted.complete)
        ok(not fake_misp.warninglists[1]["enabled"])
        ok(fake_misp.warninglists[0]["enabled"])
        taxonomy = await fleet.set_taxonomy("tlp", True)
        ok(taxonomy.partial)
        ok(fake_misp.taxonomies[1]["enabled"])
        eq(taxonomy.failed_servers, ["beta"])
        contains(taxonomy.errors["beta"].message, "does not exist")
        disabled = await fleet.set_taxonomy("tlp", False, selector=ServerSelector.names("alpha"))
        ok(disabled.complete)
        ok(not fake_misp.taxonomies[1]["enabled"])
        missing = await fleet.set_warninglist("absent-list", True)
        eq(sorted(missing.failed_servers), ["alpha", "beta"])


async def test_add_sighting_counts_per_server(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    fake_misp.attributes = [
        {
            "id": "1",
            "uuid": "aa000000-0000-4000-8000-000000000001",
            "event_id": "7",
            "type": "domain",
            "value": "evil.example",
        },
    ]
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:
        result = await fleet.add_sighting(
            "evil.example", selector=ServerSelector.names("alpha", "beta"), source="soc"
        )
    ok(result.complete)
    eq(result.results, {"alpha": 1, "beta": 0})
    eq(len(fake_misp.sightings), 1)
    eq(fake_misp.sightings[0]["attribute_uuid"], "aa000000-0000-4000-8000-000000000001")
    eq(second_fake_misp.sightings, [])


async def test_unexpected_server_failure_is_recorded_not_propagated(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    async with fleet_for(servers) as fleet:

        async def explode(name: str) -> str:
            if name == "beta":
                raise KeyError("unexpected payload shape")
            return "fine"

        envelope = await fleet._executor.run(["alpha", "beta"], explode)
    eq(envelope.results, {"alpha": "fine"})
    eq(envelope.failed_servers, ["beta"])
    eq(envelope.errors["beta"].kind, "KeyError")
    ok(not envelope.errors["beta"].retryable)
    contains(envelope.errors["beta"].message, "unexpected failure")


async def test_unexpected_failure_under_fail_fast_raises_partial_fleet_error(
    fake_misp: FakeMisp,
) -> None:
    servers = {"alpha": config_for(fake_misp, name="alpha")}
    async with fleet_for(servers) as fleet:

        async def explode(name: str) -> str:
            raise KeyError("unexpected payload shape")

        with pytest.raises(PartialFleetError) as excinfo:
            await fleet._executor.run(
                ["alpha"],
                explode,
                ExecutionOptions(failure_policy=FailurePolicy.FAIL_FAST),
            )
    eq(excinfo.value.failed_servers, ["alpha"])


class RefusingCloseClient(MispClient):
    """A real client whose shutdown fails after releasing its transport."""

    async def aclose(self) -> None:
        await super().aclose()
        raise ConnectionFailedError("transport refused to shut down")


async def test_aclose_closes_every_client_even_when_one_fails(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """A TaskGroup cancels the siblings of the first failure.

    The remaining clients' connection pools were then never released, and the
    cache still held them.
    """
    servers = {
        "research": config_for(fake_misp, name="research"),
        "production": config_for(second_fake_misp, name="production"),
    }
    fleet = fleet_for(servers)
    healthy = fleet.client("production")
    fleet._clients["research"] = RefusingCloseClient(servers["research"], api_key=API_KEY)
    with pytest.raises(ConnectionFailedError):
        await fleet.aclose()
    ok(healthy._transport._client.is_closed, "the sibling client was left open")
    eq(fleet._clients, {})


async def test_analysis_and_distribution_are_filtered_client_side(fake_misp: FakeMisp) -> None:
    """restSearch accepts these keys in the body and ignores them.

    Verified against MISP 2.5.44: every analysis level returned the whole
    dataset, so a search scoped to org-only events returned everything.
    """
    fake_misp.attributes = [
        {
            "id": "1",
            "type": "domain",
            "value": "ongoing.example",
            "Event": {"uuid": EVENT_UUID, "info": "Ongoing", "analysis": "1", "distribution": "0"},
        },
        {
            "id": "2",
            "type": "domain",
            "value": "complete.example",
            "Event": {"uuid": EVENT_UUID, "info": "Done", "analysis": "2", "distribution": "3"},
        },
    ]
    servers = {"alpha": config_for(fake_misp, name="alpha")}
    async with fleet_for(servers) as fleet:
        everything = await fleet.search(SearchQuery(), selector=ServerSelector.all())
        eq(everything.total_matches, 2)
        ongoing = await fleet.search(SearchQuery(analysis="1"), selector=ServerSelector.all())
        eq([match.value for match in ongoing.matches], ["ongoing.example"])
        shared = await fleet.search(SearchQuery(distribution="3"), selector=ServerSelector.all())
        eq([match.value for match in shared.matches], ["complete.example"])
        streamed = [
            match.value
            async for match in fleet.iter_search(
                SearchQuery(analysis="2"), selector=ServerSelector.all()
            )
        ]
        eq(streamed, ["complete.example"])


async def test_abandoned_stream_does_not_write_state_after_shutdown(
    fake_misp: FakeMisp, tmp_path: Path
) -> None:
    """Breaking out of `async for` does not close an async generator.

    Recording the query from a `finally` therefore ran at finalization time in
    a detached task, after the caller had closed the state backend, and raised
    'Cannot operate on a closed database' instead of recording anything.
    """
    from mispfleet.state.sqlite import SqliteStateBackend

    fake_misp.attributes = [
        {"id": str(index), "type": "domain", "value": f"e{index}.example"} for index in range(20)
    ]
    backend = SqliteStateBackend(tmp_path / "state.db")
    await backend.initialize()
    servers = {"alpha": config_for(fake_misp, name="alpha")}
    resolver = CredentialResolver({"memory": MemoryCredentialProvider({"alpha": API_KEY})})
    fleet = MispFleet(servers, resolver=resolver, interactive=False, state=backend)
    async for _match in fleet.iter_search(SearchQuery(), selector=ServerSelector.all()):
        break
    await fleet.aclose()
    eq(await backend.list_queries(), [])
    await backend.close()

    second = SqliteStateBackend(tmp_path / "second.db")
    await second.initialize()
    exhausted = MispFleet(servers, resolver=resolver, interactive=False, state=second)
    streamed = [
        match async for match in exhausted.iter_search(SearchQuery(), selector=ServerSelector.all())
    ]
    await exhausted.aclose()
    eq(len(streamed), 20)
    eq(len(await second.list_queries()), 1)
    await second.close()


async def test_sighting_push_reports_a_missing_capability(fake_misp: FakeMisp) -> None:
    """docs/compatibility.md promises CapabilityError naming server and capability.

    Capabilities were derived and displayed but never consulted, so a key
    without perm_sighting had its write sent anyway and rejected by MISP with
    whatever generic error it chose.
    """
    from mispfleet.exceptions import CapabilityError

    fake_misp.version_payload = {"version": "2.4.190"}
    servers = {"alpha": config_for(fake_misp, name="alpha")}
    async with fleet_for(servers) as fleet:
        # Through the fleet it is recorded per server, so the others continue.
        envelope = await fleet.add_sighting("evil.example", selector=ServerSelector.all())
        eq(envelope.errors["alpha"].kind, "CapabilityError")
        contains(envelope.errors["alpha"].message, "sightings")
        with pytest.raises(CapabilityError) as excinfo:
            await fleet.client("alpha").require_capability("sightings")
    contains(str(excinfo.value), "alpha")
    contains(str(excinfo.value), "sightings")


async def test_capability_discovery_is_probed_once_per_client(fake_misp: FakeMisp) -> None:
    servers = {"alpha": config_for(fake_misp, name="alpha")}
    async with fleet_for(servers) as fleet:
        client = fleet.client("alpha")
        await client.require_capability("sightings")
        probes = len([call for call in fake_misp.requests_seen if "getVersion" in call[1]])
        await client.require_capability("sightings")
        eq(len([call for call in fake_misp.requests_seen if "getVersion" in call[1]]), probes)


async def test_credential_failures_stay_isolated_when_clients_are_prebuilt(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """Building clients before the fan-out must not fail the whole operation.

    Credential resolution is synchronous — the prompt provider waits for a
    human — so it happens off the loop before any task starts. A server whose
    secret is missing still has to surface as that one server's error.
    """
    servers = {
        "good": config_for(fake_misp, name="good"),
        "bad": config_for(second_fake_misp, name="bad"),
    }
    resolver = CredentialResolver({"memory": MemoryCredentialProvider({"good": API_KEY})})
    async with MispFleet(servers, resolver=resolver, interactive=False) as fleet:
        first = await fleet.health()
        eq(first.successful_servers, ["good"])
        eq(first.failed_servers, ["bad"])
        # Re-running takes the already-cached path for 'good'.
        second = await fleet.health()
        eq(second.successful_servers, ["good"])
        eq(second.failed_servers, ["bad"])


class LockedKeyringProvider:
    """A keyring whose backend refuses to unlock, as a locked one does."""

    def resolve(self, key: str) -> str:
        """Fail the way a locked backend does: not with a MispFleetError."""
        raise PermissionError(f"keyring is locked, cannot read {key}")


async def test_one_servers_broken_credential_provider_does_not_sink_the_fleet(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """Client prebuild happens off the loop; its failures stay per-server.

    Suppressing the failure made the server's own task resolve again *on* the
    loop, where a blocking provider froze every sibling request. A failure that
    was not a MispFleetError escaped the prebuild and aborted the whole fan-out.
    """
    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    seed(fake_misp, "alpha")
    resolver = CredentialResolver(
        {
            "memory": MemoryCredentialProvider({"alpha": API_KEY}),
            "keyring": LockedKeyringProvider(),
        }
    )
    servers["beta"] = config_for(
        second_fake_misp,
        name="beta",
        credential=CredentialReference(provider="keyring", key="beta"),
    )
    async with MispFleet(servers, resolver=resolver, interactive=False) as fleet:
        result = await fleet.search(
            SearchQuery(value="evil.example"),
            execution=ExecutionOptions(failure_policy=FailurePolicy.CONTINUE),
        )
    eq(sorted(result.errors), ["beta"])
    contains(result.errors["beta"].message, "keyring is locked")
    ok(any(match.server == "alpha" for match in result.matches))


async def test_a_disabled_server_cannot_be_reached_by_name(fake_misp: FakeMisp) -> None:
    """Selectors refuse a disabled server; single-server commands did not.

    `event get`, `event copy --to`, `stix push` and the rest resolve through
    fleet.client(), so an operator who disabled a decommissioned instance
    could still read from — and copy events to — it.
    """
    servers = {"retired": config_for(fake_misp, name="retired", enabled=False)}
    async with fleet_for(servers) as fleet:
        with pytest.raises(InvalidConfigurationError):
            fleet.client("retired")
        with pytest.raises(InvalidConfigurationError):
            fleet.select(ServerSelector.all())


async def test_a_lost_client_build_race_is_closed_not_leaked(fake_misp: FakeMisp) -> None:
    """client() builds outside the lock so a blocking provider cannot stall
    the loop, which means two callers can build the same client at once.

    The loser's transport is already open; dropping it on the floor leaked the
    connection pool and produced an "Unclosed AsyncClient" warning.
    """
    servers = {"alpha": config_for(fake_misp, name="alpha")}
    fleet = fleet_for(servers)
    barrier = threading.Barrier(2)

    def build() -> MispClient:
        barrier.wait()
        return fleet.client("alpha")

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = (task.result() for task in [pool.submit(build), pool.submit(build)])
    eq(first, second)
    # The losing instance is held for aclose() rather than dropped.
    eq(len(fleet._discarded), 1)
    await fleet.aclose()
    eq(fleet._discarded, [])


async def test_a_closed_fleet_refuses_to_build_more_clients(fake_misp: FakeMisp) -> None:
    servers = {"alpha": config_for(fake_misp, name="alpha")}
    fleet = fleet_for(servers)
    await fleet.aclose()
    with pytest.raises(InvalidConfigurationError):
        fleet.client("alpha")


async def test_a_client_resolved_after_aclose_does_not_reopen_the_fleet(
    fake_misp: FakeMisp,
) -> None:
    """_fan_out builds clients on a thread a cancelled await does not stop.

    One finishing after aclose() used to re-populate the fleet with an open
    transport that nothing would ever close.
    """
    resolving, release = threading.Event(), threading.Event()

    class SlowProvider:
        def resolve(self, key: str) -> str:
            resolving.set()
            release.wait(10)
            return API_KEY

    servers = {"alpha": config_for(fake_misp, name="alpha")}
    fleet = MispFleet(
        servers,
        resolver=CredentialResolver({"memory": SlowProvider()}),
        interactive=False,
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        building = pool.submit(fleet.client, "alpha")
        ok(resolving.wait(10))
        closing = asyncio.ensure_future(fleet.aclose())
        await asyncio.sleep(0.05)
        ok(not closing.done(), "aclose must wait for the build already in flight")
        release.set()
        # The client aclose() is about to shut must not be handed back: its
        # httpx RuntimeError would escape the typed-error handling instead of
        # the documented configuration exit code.
        with pytest.raises(InvalidConfigurationError):
            building.result(timeout=10)
        await closing
    # One close is enough: the caller never gets a second one, so a client
    # aclose drained ahead of would stay open forever.
    eq(fleet._clients, {})
    eq(fleet._discarded, [])


async def test_a_cached_client_is_refused_once_the_fleet_is_closing(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    """aclose() waits for builds in flight, and _clients stays populated.

    Checking _closed only after the build let the cache hit hand back a client
    aclose was about to shut, whose httpx RuntimeError is not a MispFleetError
    and so escapes the typed-error handling every command relies on.
    """
    resolving, release = threading.Event(), threading.Event()

    class SlowProvider:
        def resolve(self, key: str) -> str:
            if key == "beta":
                return API_KEY
            resolving.set()
            release.wait(10)
            return API_KEY

    servers = {
        "alpha": config_for(fake_misp, name="alpha"),
        "beta": config_for(second_fake_misp, name="beta"),
    }
    fleet = MispFleet(
        servers, resolver=CredentialResolver({"memory": SlowProvider()}), interactive=False
    )
    fleet.client("beta")  # cached before anything starts closing
    with ThreadPoolExecutor(max_workers=1) as pool:
        building = pool.submit(fleet.client, "alpha")
        ok(resolving.wait(10))
        closing = asyncio.ensure_future(fleet.aclose())
        await asyncio.sleep(0.05)
        with pytest.raises(InvalidConfigurationError):
            fleet.client("beta")
        release.set()
        with pytest.raises(InvalidConfigurationError):
            building.result(timeout=10)
        await closing
    eq(fleet._clients, {})
