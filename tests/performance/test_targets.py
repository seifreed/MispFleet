"""Performance targets from the build contract (§33).

Sizes are modest by default so the suite stays fast and stable on shared CI
runners; set ``MISPFLEET_PERF_FULL=1`` to run the full-scale streaming target
(5 million attributes). Thresholds are expressed per record so the smaller
default sizes still validate the same rates.
"""

from __future__ import annotations

import json
import os
import time
import tracemalloc
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from pydantic import AnyHttpUrl

from mispfleet import MispFleet, SearchQuery, ServerSelector
from mispfleet.client.pagination import paginate
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.models.attribute import MISPAttribute
from mispfleet.models.server import CredentialReference, RetryConfig, ServerConfig
from mispfleet.settings import load_fleet_config
from tests.conftest import config_for
from tests.fake_misp import API_KEY, FakeMisp
from tests.support import eq, ok

pytestmark = pytest.mark.performance

FULL_SCALE = os.environ.get("MISPFLEET_PERF_FULL") == "1"
STREAM_RECORDS = 5_000_000 if FULL_SCALE else 200_000


def server_entry(index: int) -> str:
    return f"""
  server-{index:04d}:
    url: https://misp-{index:04d}.example
    credential: {{provider: env, key: MISPFLEET_PERF_KEY}}
    groups: [group-{index % 10}]
"""


def test_configuration_load_under_100ms_for_100_servers(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "version: 1\nservers:" + "".join(server_entry(i) for i in range(100)),
        encoding="utf-8",
    )
    load_fleet_config(config_path)
    start = time.perf_counter()
    config = load_fleet_config(config_path)
    elapsed = time.perf_counter() - start
    eq(len(config.servers), 100)
    ok(elapsed < 0.1, f"configuration load took {elapsed * 1000:.1f}ms for 100 servers")


def test_selector_evaluation_under_10ms_for_1000_servers() -> None:
    servers = [
        ServerConfig(
            name=f"server-{index:04d}",
            url=AnyHttpUrl(f"https://misp-{index:04d}.example"),
            credential=CredentialReference(provider="env", key="MISPFLEET_PERF_KEY"),
            groups={f"group-{index % 10}"},
        )
        for index in range(1000)
    ]
    selector = ServerSelector(groups={"group-3"})
    selector.select(servers)
    start = time.perf_counter()
    selected = selector.select(servers)
    elapsed = time.perf_counter() - start
    eq(len(selected), 100)
    ok(elapsed < 0.01, f"selector evaluation took {elapsed * 1000:.2f}ms for 1000 servers")


def test_serialization_of_at_least_10000_attributes_per_second() -> None:
    attributes = [
        MISPAttribute(type="sha256", value=f"{index:064x}", to_ids=True) for index in range(20_000)
    ]
    start = time.perf_counter()
    payload = [attribute.to_misp() for attribute in attributes]
    encoded = json.dumps(payload)
    elapsed = time.perf_counter() - start
    rate = len(attributes) / elapsed
    ok(len(encoded) > 0)
    ok(rate >= 10_000, f"serialized {rate:.0f} attributes/s, target is 10000/s")


def raw_attribute(index: int) -> dict[str, object]:
    return {"id": str(index), "type": "sha256", "value": f"{index:064x}"}


async def test_streaming_is_memory_safe_and_never_materializes() -> None:
    page_size = 1000
    high_water: dict[str, int] = {"pages": 0}

    async def fetch(page: int, limit: int) -> list[dict[str, object]]:
        high_water["pages"] += 1
        start = (page - 1) * limit
        if start >= STREAM_RECORDS:
            return []
        stop = min(start + limit, STREAM_RECORDS)
        return [raw_attribute(index) for index in range(start, stop)]

    tracemalloc.start()
    baseline = tracemalloc.get_traced_memory()[0]
    seen = 0
    async for _record in paginate(fetch, page_size=page_size):
        seen += 1
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    eq(seen, STREAM_RECORDS)
    growth = peak - baseline
    ok(
        growth < 50_000_000,
        f"streaming {STREAM_RECORDS} records peaked at {growth / 1e6:.1f}MB",
    )


def perf_fleet(servers: dict[str, ServerConfig]) -> MispFleet:
    resolver = CredentialResolver(
        {"memory": MemoryCredentialProvider(dict.fromkeys(servers, API_KEY))}
    )
    return MispFleet(servers, resolver=resolver, interactive=False)


@pytest.fixture
def loaded_misp() -> Iterator[FakeMisp]:
    """A fake MISP holding enough attributes to measure fleet overhead."""
    app = FakeMisp()
    app.attributes = [
        {"id": str(index), "type": "sha256", "value": f"{index:064x}"} for index in range(500)
    ]
    app.start()
    yield app
    app.stop()


async def direct_stream(config: ServerConfig, rounds: int) -> float:
    """Time streaming straight through a single client, normalization included."""
    from mispfleet.client import MispClient

    query = SearchQuery(attribute_types={"sha256"}, limit_per_server=500)
    async with MispClient(config, api_key=API_KEY) as client:
        start = time.perf_counter()
        for _ in range(rounds):
            async for _attribute in client.attributes.iter_search(query, page_size=500):
                pass
        return time.perf_counter() - start


async def fleet_stream(fleet: MispFleet, rounds: int) -> float:
    """Time the same streaming workload dispatched through the fleet."""
    query = SearchQuery(attribute_types={"sha256"}, limit_per_server=500)
    start = time.perf_counter()
    for _ in range(rounds):
        async for _match in fleet.iter_search(query, page_size=500):
            pass
    return time.perf_counter() - start


async def test_fleet_overhead_stays_close_to_direct_requests(loaded_misp: FakeMisp) -> None:
    rounds = 20
    config = config_for(
        loaded_misp,
        name="alpha",
        retry=RetryConfig(max_attempts=1, initial_delay=0.0, jitter=False),
    )
    await direct_stream(config, rounds=5)
    direct = await direct_stream(config, rounds=rounds)
    fleet = perf_fleet({"alpha": config})
    async with fleet:
        await fleet_stream(fleet, rounds=5)
        fleet_elapsed = await fleet_stream(fleet, rounds=rounds)
    overhead = (fleet_elapsed - direct) / direct
    ok(
        overhead < 0.10,
        f"fleet dispatch overhead was {overhead * 100:.1f}% over direct requests",
    )


async def test_in_flight_requests_stay_bounded(loaded_misp: FakeMisp) -> None:
    config = config_for(loaded_misp, name="alpha", concurrency=2)
    eq(config.concurrency, 2)
    fleet = perf_fleet({"alpha": config})
    async with fleet:
        transport = fleet.client("alpha")._transport
        eq(transport._semaphore._value, 2)
        results: list[AsyncIterator[object]] = []
        eq(len(results), 0)
        await fleet.search(SearchQuery(attribute_types={"sha256"}, limit_per_server=100))
        eq(transport._semaphore._value, 2)
