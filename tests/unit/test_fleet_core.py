"""Unit tests for registry, selector, executor and search normalization."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import AnyHttpUrl

from mispfleet.exceptions import (
    InvalidConfigurationError,
    NotFoundError,
    PartialFleetError,
    RequestTimeoutError,
)
from mispfleet.fleet.executor import FleetExecutor
from mispfleet.fleet.registry import ServerRegistry
from mispfleet.fleet.selector import ServerSelector
from mispfleet.models.common import ExecutionOptions, FailurePolicy, ServerRole
from mispfleet.models.query import SearchQuery
from mispfleet.models.server import CredentialReference, ServerConfig
from mispfleet.services.search import (
    collect_query_limit,
    group_matches,
    normalize_match,
    normalized_value,
)
from tests.support import contains, eq, ok


def server(name: str, **overrides: object) -> ServerConfig:
    fields: dict[str, object] = {
        "name": name,
        "url": AnyHttpUrl(f"https://{name}.example"),
        "credential": CredentialReference(provider="env", key=name.upper()),
    }
    fields.update(overrides)
    return ServerConfig.model_validate(fields)


FLEET = {
    "production": server("production", role=ServerRole.PRIMARY, groups={"internal", "all"}),
    "research": server("research", role=ServerRole.RESEARCH, groups={"internal", "all"}),
    "partner": server(
        "partner",
        role=ServerRole.PARTNER,
        groups={"partners", "all"},
        tags={"customer:acme"},
        read_only=True,
    ),
    "legacy": server("legacy", enabled=False, groups={"all"}),
}


def test_registry_lookups() -> None:
    registry = ServerRegistry(FLEET)
    eq(registry.get("production").name, "production")
    eq(registry.names(), ["production", "research", "partner", "legacy"])
    eq([config.name for config in registry.enabled()], ["production", "research", "partner"])
    eq(registry.groups(), {"internal", "partners", "all"})
    with pytest.raises(InvalidConfigurationError):
        registry.get("missing")


def test_selector_variants() -> None:
    servers = list(FLEET.values())
    eq(
        [c.name for c in ServerSelector.all().select(servers)],
        ["production", "research", "partner"],
    )
    eq([c.name for c in ServerSelector.names("research").select(servers)], ["research"])
    eq([c.name for c in ServerSelector.group("partners").select(servers)], ["partner"])
    eq([c.name for c in ServerSelector.tag("customer:acme").select(servers)], ["partner"])
    eq(
        [c.name for c in ServerSelector.role(ServerRole.PRIMARY).select(servers)],
        ["production"],
    )
    eq(
        [c.name for c in ServerSelector.all().exclude("production").select(servers)],
        ["research", "partner"],
    )
    ok(ServerSelector.all().is_explicit)
    ok(not ServerSelector().is_explicit)
    eq(ServerSelector.group("nonexistent").select(servers), [])


async def test_executor_continue_policy_collects_partial_results() -> None:
    async def operation(name: str) -> str:
        if name == "bad":
            raise RequestTimeoutError("deadline exceeded")
        return f"ok-{name}"

    result = await FleetExecutor().run(["good", "bad"], operation)
    eq(result.successful_servers, ["good"])
    eq(result.failed_servers, ["bad"])
    eq(result.results["good"], "ok-good")
    eq(result.errors["bad"].kind, "RequestTimeoutError")
    ok(result.partial)
    ok(not result.complete)
    ok(result.duration_ms >= 0.0)


async def test_executor_complete_success() -> None:
    async def operation(name: str) -> int:
        return len(name)

    result = await FleetExecutor().run(["a", "bb"], operation)
    ok(result.complete)
    eq(result.results, {"a": 1, "bb": 2})


async def test_executor_fail_fast_raises_partial_fleet_error() -> None:
    async def operation(name: str) -> str:
        raise NotFoundError("nope")

    options = ExecutionOptions(failure_policy=FailurePolicy.FAIL_FAST)
    with pytest.raises(PartialFleetError) as excinfo:
        await FleetExecutor().run(["one", "two"], operation, options)
    contains(excinfo.value.failed_servers, "one")


async def test_executor_require_all_raises_after_completion() -> None:
    async def operation(name: str) -> str:
        if name == "bad":
            raise NotFoundError("nope")
        return "ok"

    options = ExecutionOptions(failure_policy=FailurePolicy.REQUIRE_ALL)
    with pytest.raises(PartialFleetError) as excinfo:
        await FleetExecutor().run(["good", "bad"], operation, options)
    eq(excinfo.value.failed_servers, ["bad"])


async def test_executor_require_any_tolerates_partial_but_not_total_failure() -> None:
    async def operation(name: str) -> str:
        if name == "bad":
            raise NotFoundError("nope")
        return "ok"

    options = ExecutionOptions(failure_policy=FailurePolicy.REQUIRE_ANY)
    result = await FleetExecutor().run(["good", "bad"], operation, options)
    ok(result.partial)

    async def always_fail(name: str) -> str:
        raise NotFoundError("nope")

    with pytest.raises(PartialFleetError):
        await FleetExecutor().run(["one"], always_fail, options)


def test_normalize_match_full_and_minimal() -> None:
    now = datetime.now(tz=UTC)
    raw = {
        "id": "11",
        "uuid": "1f2b8a1e-0000-4000-8000-000000000001",
        "event_id": "7",
        "type": "domain",
        "category": "Network activity",
        "value": "EVIL.example ",
        "Tag": [{"name": "tlp:green"}],
        "Event": {"uuid": "9c5c1c2e-0000-4000-8000-00000000000e", "info": "Campaign"},
    }
    match = normalize_match("production", raw, now)
    eq(match.server, "production")
    eq(match.attribute_id, "11")
    eq(match.event_info, "Campaign")
    eq(match.tags, {"tlp:green"})
    eq(match.fetched_at, now)
    minimal = normalize_match("production", {"uuid": "not-a-uuid"}, now)
    eq(minimal.attribute_uuid, None)
    eq(minimal.value, None)
    eq(minimal.event_uuid, None)


def test_group_matches_by_value_type_and_event_uuid() -> None:
    now = datetime.now(tz=UTC)
    event_uuid = "9c5c1c2e-0000-4000-8000-00000000000e"
    left = normalize_match(
        "production",
        {"type": "domain", "value": "Evil.example", "Event": {"uuid": event_uuid}},
        now,
    )
    right = normalize_match(
        "research",
        {"type": "domain", "value": "evil.example", "Event": {"uuid": event_uuid}},
        now,
    )
    lonely = normalize_match("partner", {"type": "sha256", "value": "aa" * 32}, now)
    valueless = normalize_match("partner", {"Event": {"uuid": event_uuid}}, now)
    groups = group_matches([left, right, lonely, valueless])
    eq(len(groups), 2)
    eq(groups[0].level, "same-value-and-type")
    eq(groups[0].key, "domain|evil.example")
    eq({m.server for m in groups[0].matches}, {"production", "research"})
    eq(groups[1].level, "same-uuid")
    eq(groups[1].key, event_uuid)


def test_normalized_value_and_query_limit() -> None:
    eq(normalized_value("  Evil.EXAMPLE  "), "evil.example")
    eq(collect_query_limit(SearchQuery(), 1000), 1000)
    eq(collect_query_limit(SearchQuery(limit_per_server=10), 1000), 10)
    eq(collect_query_limit(SearchQuery(limit_per_server=5000), 1000), 1000)
