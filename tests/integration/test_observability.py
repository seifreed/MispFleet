"""Integration tests for metrics callbacks, log context and transport knobs."""

from __future__ import annotations

import logging

import pytest

from mispfleet import MetricsSink, MispFleet, SearchQuery
from mispfleet.client import MispClient
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.exceptions import ResponseTooLargeError
from mispfleet.models.server import RetryConfig, ServerConfig
from mispfleet.policies.base import PolicySpec, RejectRules
from tests.conftest import config_for
from tests.fake_misp import API_KEY, FakeMisp
from tests.support import contains, eq, ok

EVENT_UUID = "9c5c1c2e-0000-4000-8000-00000000000e"


class RecordingSink(MetricsSink):
    """Collects every metrics hook invocation for assertions."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    def on_request(self, server: str, endpoint: str, duration_seconds: float, status: int) -> None:
        self.calls.append(("request", (server, endpoint, status)))

    def on_retry(self, server: str, endpoint: str) -> None:
        self.calls.append(("retry", (server, endpoint)))

    def on_error(self, server: str, endpoint: str, kind: str) -> None:
        self.calls.append(("error", (server, endpoint, kind)))

    def on_page(self, server: str, page: int, records: int) -> None:
        self.calls.append(("page", (server, page, records)))

    def on_records(self, server: str, records: int) -> None:
        self.calls.append(("records", (server, records)))

    def on_availability(self, server: str, available: bool) -> None:
        self.calls.append(("availability", (server, available)))

    def on_policy_rejection(self, policy: str) -> None:
        self.calls.append(("policy-rejection", (policy,)))

    def on_plan_validation_failure(self, plan_kind: str) -> None:
        self.calls.append(("plan-failure", (plan_kind,)))

    def kinds(self) -> set[str]:
        return {name for name, _ in self.calls}


def observed_fleet(
    servers: dict[str, ServerConfig],
    sink: MetricsSink,
    policies: dict[str, PolicySpec] | None = None,
) -> MispFleet:
    """Build a fleet wired to a metrics sink and in-memory credentials."""
    resolver = CredentialResolver(
        {"memory": MemoryCredentialProvider(dict.fromkeys(servers, API_KEY))}
    )
    return MispFleet(servers, policies=policies, resolver=resolver, interactive=False, metrics=sink)


def seed(app: FakeMisp) -> None:
    app.add_event(
        {
            "id": "7",
            "uuid": EVENT_UUID,
            "info": "Campaign",
            "Tag": [{"name": "tlp:green"}],
            "Attribute": [{"type": "domain", "value": "evil.example"}],
        }
    )
    app.attributes = [{"id": "1", "type": "domain", "value": "evil.example"}]


async def test_metrics_fire_for_search_and_health(fake_misp: FakeMisp) -> None:
    seed(fake_misp)
    sink = RecordingSink()
    fleet = observed_fleet({"alpha": config_for(fake_misp, name="alpha")}, sink)
    async with fleet:
        await fleet.search(SearchQuery(value="evil.example"))
        await fleet.health()
    ok({"request", "page", "records", "availability"} <= sink.kinds())
    availability = [args for name, args in sink.calls if name == "availability"]
    contains(availability, ("alpha", True))


async def test_metrics_fire_for_retry_and_error(fake_misp: FakeMisp) -> None:
    seed(fake_misp)
    sink = RecordingSink()
    config = config_for(
        fake_misp,
        name="alpha",
        retry=RetryConfig(max_attempts=2, initial_delay=0.0, jitter=False),
    )
    async with MispClient(config, api_key=API_KEY, metrics=sink) as client:
        fake_misp.close_next = True
        version = await client.system.version()
        eq(version.get("version"), "2.4.190")
    ok({"retry", "error", "request"} <= sink.kinds())
    errors = [args for name, args in sink.calls if name == "error"]
    eq(errors[0][2], "transport")


async def test_metrics_fire_for_policy_and_plan_failures(
    fake_misp: FakeMisp, second_fake_misp: FakeMisp
) -> None:
    seed(fake_misp)
    sink = RecordingSink()
    fleet = observed_fleet(
        {
            "alpha": config_for(fake_misp, name="alpha"),
            "beta": config_for(second_fake_misp, name="beta"),
        },
        sink,
        policies={"strict": PolicySpec(reject_if=RejectRules(tags={"tlp:green"}))},
    )
    async with fleet:
        plan = await fleet.plan_copy(EVENT_UUID, "alpha", "beta", policy="strict")
    ok(plan.blocking_errors)
    ok({"policy-rejection", "plan-failure"} <= sink.kinds())


async def test_transport_logs_carry_operation_context(fake_misp: FakeMisp) -> None:
    seed(fake_misp)
    records: list[logging.LogRecord] = []

    class Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    transport_logger = logging.getLogger("mispfleet.client.transport")
    handler = Capture(level=logging.DEBUG)
    previous_level = transport_logger.level
    transport_logger.addHandler(handler)
    transport_logger.setLevel(logging.DEBUG)
    try:
        fleet = observed_fleet({"alpha": config_for(fake_misp, name="alpha")}, MetricsSink())
        async with fleet:
            await fleet.health()
        async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
            await client.system.version()
    finally:
        transport_logger.removeHandler(handler)
        transport_logger.setLevel(previous_level)
    tagged = [r for r in records if getattr(r, "server", None) == "alpha"]
    ok(tagged)
    ok(all(hasattr(r, "request_id") and hasattr(r, "endpoint") for r in tagged))
    ok(any(hasattr(r, "operation_id") for r in tagged))
    direct = [r for r in records if getattr(r, "server", None) == "test-server"]
    ok(direct)
    ok(all(not hasattr(r, "operation_id") for r in direct))


async def test_http2_and_keepalive_configuration(fake_misp: FakeMisp) -> None:
    seed(fake_misp)
    config = config_for(
        fake_misp,
        name="alpha",
        http2=True,
        max_keepalive_connections=2,
        keepalive_expiry=5.0,
        max_response_bytes=1_000_000,
    )
    async with MispClient(config, api_key=API_KEY) as client:
        version = await client.system.version()
    eq(version.get("version"), "2.4.190")


async def test_response_limit_comes_from_config(fake_misp: FakeMisp) -> None:
    seed(fake_misp)
    config = config_for(fake_misp, name="alpha", max_response_bytes=1)
    async with MispClient(config, api_key=API_KEY) as client:
        with pytest.raises(ResponseTooLargeError):
            await client.system.version()
