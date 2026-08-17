"""Contract tests against a real MISP release.

These tests only run when a live MISP instance is provided through
``MISPFLEET_CONTRACT_URL`` and ``MISPFLEET_CONTRACT_KEY``; otherwise they
skip cleanly so the normal suite stays hermetic. See
``tests/contract/docker-compose.yml`` and ``docs/compatibility.md``.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
from pydantic import AnyHttpUrl

from mispfleet.client import MispClient
from mispfleet.models.attribute import MISPAttribute, MISPObject
from mispfleet.models.event import MISPEvent
from mispfleet.models.query import SearchQuery
from mispfleet.models.server import CredentialReference, RetryConfig, ServerConfig
from tests.support import contains, eq, ok

CONTRACT_URL = os.environ.get("MISPFLEET_CONTRACT_URL")
CONTRACT_KEY = os.environ.get("MISPFLEET_CONTRACT_KEY")
CONTRACT_VERIFY_TLS = os.environ.get("MISPFLEET_CONTRACT_VERIFY_TLS", "0") == "1"
# The stock misp-objects "file" template, present in every release.
FILE_TEMPLATE_UUID = "688c46fb-5edb-40a3-8273-1af7923e2215"

pytestmark = [
    pytest.mark.contract,
    pytest.mark.skipif(
        not (CONTRACT_URL and CONTRACT_KEY),
        reason="set MISPFLEET_CONTRACT_URL and MISPFLEET_CONTRACT_KEY to run contract tests",
    ),
]


def contract_config() -> ServerConfig:
    """Server configuration pointing at the live contract instance."""
    return ServerConfig(
        name="contract",
        url=AnyHttpUrl(CONTRACT_URL or ""),
        credential=CredentialReference(provider="memory", key="contract"),
        verify_tls=CONTRACT_VERIFY_TLS,
        allow_insecure_http=True,
        request_timeout=30.0,
        connect_timeout=15.0,
        retry=RetryConfig(max_attempts=2, initial_delay=0.5, jitter=False),
    )


@pytest.fixture
async def contract_client() -> AsyncIterator[MispClient]:
    """A client bound to the live MISP instance under test."""
    async with MispClient(contract_config(), api_key=CONTRACT_KEY or "") as client:
        yield client


async def test_version_endpoint_reports_supported_release(contract_client: MispClient) -> None:
    version = await contract_client.system.version()
    ok("version" in version)
    contains(str(version["version"]), "2.")


async def test_capabilities_include_rest_search(contract_client: MispClient) -> None:
    capabilities = await contract_client.system.capabilities()
    ok("rest-search" in capabilities)
    ok("events" in capabilities)


async def test_attribute_rest_search_accepts_the_full_query_model(
    contract_client: MispClient,
) -> None:
    query = SearchQuery(
        attribute_types={"domain", "ip-dst"},
        limit_per_server=5,
        include_deleted=False,
        enforce_warninglists=False,
    )
    matches = await contract_client.attributes.search(query, limit=5)
    ok(isinstance(matches, list))


async def test_object_templates_are_listable(contract_client: MispClient) -> None:
    templates = await contract_client.templates.list()
    ok(isinstance(templates, list))


async def test_unknown_event_raises_not_found(contract_client: MispClient) -> None:
    from mispfleet.exceptions import NotFoundError

    with pytest.raises(NotFoundError):
        await contract_client.events.get("00000000-0000-4000-8000-000000000000")


async def test_search_pagination_terminates(contract_client: MispClient) -> None:
    seen = 0
    async for _attribute in contract_client.attributes.iter_search(
        SearchQuery(limit_per_server=10), page_size=5
    ):
        seen += 1
    eq(seen, min(seen, 10))


async def test_an_event_with_an_object_survives_the_round_trip(
    contract_client: MispClient,
) -> None:
    """MISP discards an object that lacks its template metadata, silently.

    Without meta-category, description, template_uuid and template_version —
    and object_relation on each attribute — the event is created and every
    object is dropped, so a copy reported success and delivered no objects.
    """
    event_uuid, object_uuid = str(uuid4()), str(uuid4())
    event = MISPEvent(
        uuid=event_uuid,
        info="mispfleet contract: object round trip",
        objects=[
            MISPObject(
                uuid=object_uuid,
                name="file",
                template_uuid=FILE_TEMPLATE_UUID,
                template_version="1",
                meta_category="file",
                description="File object",
                attributes=[
                    MISPAttribute(
                        uuid=str(uuid4()),
                        type="md5",
                        value="a" * 32,
                        object_relation="md5",
                        category="Payload delivery",
                    )
                ],
            )
        ],
    )
    await contract_client.events.add(event)
    try:
        stored = await contract_client.events.get(event_uuid)
        eq(len(stored.objects), 1)
        eq(stored.objects[0].uuid, object_uuid)
        eq(stored.objects[0].meta_category, "file")
        eq([(a.type, a.object_relation) for a in stored.objects[0].attributes], [("md5", "md5")])
    finally:
        await contract_client.events.delete(event_uuid)
