"""Integration tests for the OpenCTI client against a real local server."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from mispfleet.exceptions import (
    APIError,
    AuthenticationError,
    ConnectionFailedError,
    InvalidResponseError,
    MispServerError,
)
from mispfleet.integrations import OpenCTIClient
from mispfleet.models.attribute import MISPAttribute
from mispfleet.models.event import MISPEvent
from mispfleet.output.stix import event_to_stix_bundle
from tests.fake_opencti import TOKEN, VERSION, FakeOpenCTI
from tests.httpserver import serve
from tests.support import contains, eq, ok


@pytest.fixture
def fake_opencti() -> Iterator[FakeOpenCTI]:
    yield from serve(FakeOpenCTI())


def sample_bundle() -> dict[str, object]:
    event = MISPEvent(
        uuid="9c5c1c2e-0000-4000-8000-00000000000e",
        info="Campaign",
        attributes=[MISPAttribute(type="domain", value="evil.example")],
    )
    bundle, _ = event_to_stix_bundle(event)
    return bundle


async def test_version_and_push(fake_opencti: FakeOpenCTI) -> None:
    async with OpenCTIClient(fake_opencti.url, TOKEN) as client:
        eq(await client.version(), VERSION)
        work_id = await client.push_bundle(sample_bundle())
        eq(work_id, "work-1")
    eq(len(fake_opencti.pushed), 1)
    eq(fake_opencti.pushed[0]["type"], "bundle")


async def test_invalid_token_is_authentication_error(fake_opencti: FakeOpenCTI) -> None:
    async with OpenCTIClient(fake_opencti.url, "wrong-token") as client:
        with pytest.raises(AuthenticationError):
            await client.version()


async def test_graphql_errors_map_to_api_error(fake_opencti: FakeOpenCTI) -> None:
    fake_opencti.graphql_error = "insufficient capabilities"
    async with OpenCTIClient(fake_opencti.url, TOKEN) as client:
        with pytest.raises(APIError) as excinfo:
            await client.push_bundle(sample_bundle())
    contains(str(excinfo.value), "insufficient capabilities")


async def test_non_standard_error_payloads_still_map_to_api_error(
    fake_opencti: FakeOpenCTI,
) -> None:
    """A proxy answering with a bare string was iterated character by character.

    That turned a typed APIError into an untyped AttributeError.
    """
    fake_opencti.raw_errors = "unauthorized"
    async with OpenCTIClient(fake_opencti.url, TOKEN) as client:
        with pytest.raises(APIError) as excinfo:
            await client.push_bundle(sample_bundle())
    contains(str(excinfo.value), "unauthorized")


async def test_error_entries_without_a_message_key_are_summarized(
    fake_opencti: FakeOpenCTI,
) -> None:
    fake_opencti.raw_errors = ["plain string entry", {"code": 42}]
    async with OpenCTIClient(fake_opencti.url, TOKEN) as client:
        with pytest.raises(APIError) as excinfo:
            await client.push_bundle(sample_bundle())
    contains(str(excinfo.value), "plain string entry")


async def test_server_errors_map_to_server_error(fake_opencti: FakeOpenCTI) -> None:
    fake_opencti.status = 500
    async with OpenCTIClient(fake_opencti.url, TOKEN) as client:
        with pytest.raises(MispServerError):
            await client.version()


async def test_non_json_response_is_typed(fake_opencti: FakeOpenCTI) -> None:
    fake_opencti.reply_html = True
    async with OpenCTIClient(fake_opencti.url, TOKEN) as client:
        with pytest.raises(InvalidResponseError):
            await client.version()


async def test_connection_failure_is_typed() -> None:
    async with OpenCTIClient("http://127.0.0.1:9", TOKEN, timeout=0.5) as client:
        with pytest.raises(ConnectionFailedError):
            await client.version()


async def test_timeout_is_typed(fake_opencti: FakeOpenCTI) -> None:
    from mispfleet.exceptions import RequestTimeoutError

    async with OpenCTIClient(fake_opencti.url, TOKEN, timeout=0.000001) as client:
        with pytest.raises((RequestTimeoutError, ConnectionFailedError)):
            await client.version()


async def test_unknown_operation_returns_graphql_error(fake_opencti: FakeOpenCTI) -> None:
    async with OpenCTIClient(fake_opencti.url, TOKEN) as client:
        with pytest.raises(APIError):
            await client._graphql("query { unknown }")
    ok(True)


async def test_unexpected_opencti_shapes_raise_typed_errors() -> None:
    """A server that is not OpenCTI must not leak KeyError to the caller."""
    from mispfleet.exceptions import InvalidResponseError
    from mispfleet.integrations.opencti import _field

    with pytest.raises(InvalidResponseError) as missing:
        _field({"about": {}}, "about", "version")
    contains(missing.value.message, "about.version")
    with pytest.raises(InvalidResponseError):
        _field({}, "stixBundlePush")
    with pytest.raises(InvalidResponseError):
        _field(["not", "an", "object"], "about", "version")


async def test_json_array_response_is_an_invalid_response(fake_opencti: FakeOpenCTI) -> None:
    from mispfleet.exceptions import InvalidResponseError

    fake_opencti.reply_json_array = True
    async with OpenCTIClient(fake_opencti.url, TOKEN) as client:
        with pytest.raises(InvalidResponseError) as raised:
            await client.version()
    contains(raised.value.message, "not an object")
