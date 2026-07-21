"""Integration tests for the single-server client and pagination."""

from __future__ import annotations

from typing import Any

import pytest

from mispfleet.client import MispClient
from mispfleet.client.capabilities import capabilities_from_version
from mispfleet.client.pagination import paginate
from mispfleet.credentials import CredentialResolver, MemoryCredentialProvider
from mispfleet.exceptions import NotFoundError
from mispfleet.models.event import MISPEvent
from mispfleet.models.query import SearchQuery
from tests.conftest import config_for
from tests.fake_misp import API_KEY, FakeMisp
from tests.support import contains, eq, ne, ok

RAW_EVENT: dict[str, Any] = {
    "id": "7",
    "uuid": "9c5c1c2e-0000-4000-8000-00000000000e",
    "info": "Campaign X",
    "date": "2026-01-01",
    "published": True,
    "Attribute": [{"type": "domain", "value": "evil.example"}],
}


def attribute(index: int) -> dict[str, Any]:
    return {"type": "sha256", "value": f"{index:064x}", "event_id": str(index)}


async def test_client_event_get_by_uuid_and_id(fake_misp: FakeMisp) -> None:
    fake_misp.add_event(dict(RAW_EVENT))
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        by_uuid = await client.events.get(RAW_EVENT["uuid"])
        eq(by_uuid.info, "Campaign X")
        by_id = await client.events.get("7")
        eq(by_id.uuid, RAW_EVENT["uuid"])
        with pytest.raises(NotFoundError):
            await client.events.get("missing")


async def test_client_event_add_and_update(fake_misp: FakeMisp) -> None:
    event = MISPEvent.from_misp(RAW_EVENT)
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        created = await client.events.add(event)
        eq(created.uuid, event.uuid)
        event.info = "Campaign X (updated)"
        updated = await client.events.update(event)
        eq(updated.info, "Campaign X (updated)")


async def test_client_resolves_credentials_through_resolver(fake_misp: FakeMisp) -> None:
    resolver = CredentialResolver({"memory": MemoryCredentialProvider({"test-server": API_KEY})})
    async with MispClient(config_for(fake_misp), resolver=resolver) as client:
        version = await client.system.version()
        eq(version["version"], "2.4.190")


async def test_client_capabilities_and_list_namespaces(fake_misp: FakeMisp) -> None:
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        capabilities = await client.system.capabilities()
        contains(capabilities, "sync")
        contains(capabilities, "version")
        for namespace in (
            client.tags,
            client.taxonomies,
            client.galaxies,
            client.warninglists,
            client.templates,
            client.organisations,
            client.servers,
            client.objects,
        ):
            eq(await namespace.list(), [])


def test_capabilities_from_minimal_version_payload() -> None:
    capabilities = capabilities_from_version({})
    contains(capabilities, "rest-search")
    ok("sync" not in capabilities)
    full = capabilities_from_version(
        {"version": "2.4.190", "perm_sync": 1, "perm_sighting": 1, "perm_galaxy_editor": 1}
    )
    contains(full, "sightings")
    contains(full, "galaxies")


async def test_attribute_search_filters_by_value_and_type(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [
        {"type": "domain", "value": "evil.example"},
        {"type": "sha256", "value": "aa" * 32},
    ]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        matches = await client.attributes.search(SearchQuery(value="evil.example"))
        eq(len(matches), 1)
        eq(matches[0]["type"], "domain")
        typed = await client.attributes.search(SearchQuery(attribute_types={"sha256"}))
        eq(len(typed), 1)
        both = await client.attributes.search(SearchQuery())
        eq(len(both), 2)


async def test_iter_search_streams_across_pages(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [attribute(index) for index in range(25)]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        seen = [item async for item in client.attributes.iter_search(SearchQuery(), page_size=10)]
        eq(len(seen), 25)
        eq(sorted({item.type for item in seen}), ["sha256"])
        pages = [path for method, path in fake_misp.requests_seen if method == "POST"]
        eq(len(pages), 3)


async def test_iter_search_respects_max_records(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [attribute(index) for index in range(25)]
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        seen = [
            item
            async for item in client.attributes.iter_search(
                SearchQuery(), page_size=10, max_records=12
            )
        ]
        eq(len(seen), 12)


async def test_iter_search_stops_on_non_advancing_pages(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [attribute(index) for index in range(30)]
    fake_misp.static_search = True
    warnings: list[str] = []
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        seen = [
            item
            async for item in client.attributes.iter_search(
                SearchQuery(), page_size=10, on_warning=warnings.append
            )
        ]
    eq(len(seen), 10)
    eq(len(warnings), 1)
    contains(warnings[0], "not advancing")


async def test_paginate_empty_first_page_yields_nothing() -> None:
    async def fetch_empty(page: int, limit: int) -> list[dict[str, Any]]:
        return []

    eq([item async for item in paginate(fetch_empty, page_size=1)], [])


async def test_paginate_reports_pages_to_checkpoint_callback() -> None:
    data = [[{"n": 1}, {"n": 2}], [{"n": 3}, {"n": 4}], []]
    checkpoints: list[tuple[int, int]] = []

    async def fetch(page: int, limit: int) -> list[dict[str, Any]]:
        return data[page - 1]

    def on_page(page: int, records: int) -> None:
        checkpoints.append((page, records))

    seen = [item async for item in paginate(fetch, page_size=2, on_page=on_page)]
    eq(len(seen), 4)
    eq(checkpoints, [(1, 2), (2, 4)])


async def test_paginate_resumes_from_checkpoint_page() -> None:
    requested: list[int] = []

    async def fetch(page: int, limit: int) -> list[dict[str, Any]]:
        requested.append(page)
        return [{"page": page}] if page < 4 else []

    seen = [item async for item in paginate(fetch, page_size=1, start_page=3)]
    eq(requested[0], 3)
    eq(len(seen), 1)
    ne(seen[0]["page"], 1)


async def test_client_accepts_prebuilt_transport(fake_misp: FakeMisp) -> None:
    from mispfleet.client.transport import AsyncTransport

    transport = AsyncTransport(config_for(fake_misp), API_KEY)
    async with MispClient(config_for(fake_misp), transport=transport) as client:
        version = await client.system.version()
        eq(version["version"], "2.4.190")


async def test_iter_search_repeated_page_without_warning_callback(fake_misp: FakeMisp) -> None:
    fake_misp.attributes = [attribute(index) for index in range(30)]
    fake_misp.static_search = True
    async with MispClient(config_for(fake_misp), api_key=API_KEY) as client:
        seen = [item async for item in client.attributes.iter_search(SearchQuery(), page_size=10)]
    eq(len(seen), 10)
