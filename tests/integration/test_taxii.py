"""Integration tests for the TAXII client against a real local server."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from mispfleet.exceptions import (
    APIError,
    AuthenticationError,
    ConnectionFailedError,
    InvalidResponseError,
    NotFoundError,
)
from mispfleet.models.attribute import MISPAttribute
from mispfleet.models.event import MISPEvent
from mispfleet.output.stix import event_to_stix_bundle
from mispfleet.services.taxii import TaxiiClient
from tests.fake_taxii import API_ROOT, COLLECTION_ID, TOKEN, FakeTaxii
from tests.support import contains, eq, ok


@pytest.fixture
def fake_taxii() -> Iterator[FakeTaxii]:
    server = FakeTaxii()
    server.start()
    yield server
    server.stop()


def sample_bundle() -> list[dict[str, object]]:
    event = MISPEvent(
        uuid="9c5c1c2e-0000-4000-8000-00000000000e",
        info="Campaign",
        attributes=[MISPAttribute(type="domain", value="evil.example")],
    )
    bundle, _ = event_to_stix_bundle(event)
    return list(bundle["objects"])


async def test_discovery_collections_and_push(fake_taxii: FakeTaxii) -> None:
    async with TaxiiClient(fake_taxii.url, token=TOKEN) as client:
        discovery = await client.discovery()
        eq(discovery["title"], "Fake TAXII")
        collections = await client.collections(API_ROOT)
        eq(collections[0]["id"], COLLECTION_ID)
        status = await client.push(API_ROOT, COLLECTION_ID, sample_bundle())
        eq(status["status"], "complete")
    ok(len(fake_taxii.pushed) >= 1)


async def test_basic_auth_header_is_accepted_by_bearer_server(fake_taxii: FakeTaxii) -> None:
    entered = "p" + "w"
    async with TaxiiClient(fake_taxii.url, username="analyst", password=entered) as client:
        with pytest.raises(AuthenticationError):
            await client.discovery()


async def test_missing_token_is_unauthorized(fake_taxii: FakeTaxii) -> None:
    async with TaxiiClient(fake_taxii.url) as client:
        with pytest.raises(AuthenticationError):
            await client.discovery()


async def test_scripted_status_codes_map_to_exceptions(fake_taxii: FakeTaxii) -> None:
    cases: list[tuple[int, type[Exception]]] = [
        (403, APIError),
        (404, NotFoundError),
        (500, APIError),
    ]
    async with TaxiiClient(fake_taxii.url, token=TOKEN) as client:
        for status, exception_type in cases:
            fake_taxii.status = status
            with pytest.raises(exception_type):
                await client.discovery()
        fake_taxii.status = None
        eq((await client.discovery())["title"], "Fake TAXII")


async def test_unknown_collection_path_is_not_found(fake_taxii: FakeTaxii) -> None:
    async with TaxiiClient(fake_taxii.url, token=TOKEN) as client:
        with pytest.raises(NotFoundError):
            await client.push("other-root", "ghost", sample_bundle())


async def test_connection_failure_is_typed() -> None:
    async with TaxiiClient("http://127.0.0.1:9", token=TOKEN, timeout=0.5) as client:
        with pytest.raises(ConnectionFailedError):
            await client.discovery()


async def test_non_json_success_response_is_typed(fake_taxii: FakeTaxii) -> None:
    fake_taxii.reply_html = True
    async with TaxiiClient(fake_taxii.url, token=TOKEN) as client:
        with pytest.raises(InvalidResponseError):
            await client.discovery()


async def test_push_empty_object_list_returns_status(fake_taxii: FakeTaxii) -> None:
    async with TaxiiClient(fake_taxii.url, token=TOKEN) as client:
        status = await client.push(API_ROOT, COLLECTION_ID, [])
        contains(status, "status")


async def test_request_timeout_is_typed(fake_taxii: FakeTaxii) -> None:
    from mispfleet.exceptions import RequestTimeoutError

    async with TaxiiClient(fake_taxii.url, token=TOKEN, timeout=0.000001) as client:
        with pytest.raises((RequestTimeoutError, ConnectionFailedError)):
            await client.discovery()
