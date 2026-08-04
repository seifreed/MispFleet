"""Public asynchronous single-server MISP client."""

from __future__ import annotations

from collections.abc import AsyncIterator
from types import TracebackType
from typing import Any
from urllib.parse import quote

from mispfleet.client.capabilities import capabilities_from_version
from mispfleet.client.pagination import WarningCallback, paginate
from mispfleet.client.transport import AsyncTransport
from mispfleet.credentials import CredentialResolver
from mispfleet.credentials.base import default_resolver
from mispfleet.models.attribute import MISPAttribute
from mispfleet.models.event import MISPEvent
from mispfleet.models.query import SearchQuery
from mispfleet.models.server import ServerConfig


class EventsNamespace:
    """Event retrieval and mutation endpoints."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def get(self, event_id: str) -> MISPEvent:
        """Fetch one event by UUID or numeric identifier."""
        data = await self._transport.request("GET", f"/events/view/{quote(event_id, safe='')}")
        return MISPEvent.from_misp(data)

    async def index(self, tags: set[str] | None = None) -> list[dict[str, Any]]:
        """List event metadata, optionally filtered by event tags."""
        body: dict[str, Any] = {}
        if tags:
            body["tag"] = sorted(tags)
        data = await self._transport.request("POST", "/events/index", json_body=body)
        return list(data)

    async def add(self, event: MISPEvent) -> MISPEvent:
        """Create a new event; never retried because creation is not idempotent."""
        data = await self._transport.request(
            "POST", "/events/add", json_body={"Event": event.to_misp()}, idempotent=False
        )
        return MISPEvent.from_misp(data)

    async def update(self, event: MISPEvent) -> MISPEvent:
        """Update an existing event identified by its UUID."""
        data = await self._transport.request(
            "POST",
            f"/events/edit/{quote(event.uuid, safe='')}",
            json_body={"Event": event.to_misp()},
            idempotent=False,
        )
        return MISPEvent.from_misp(data)


class AttributesNamespace:
    """Attribute search endpoints."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def get(self, attribute_id: str) -> MISPAttribute:
        """Fetch one attribute by UUID or numeric id."""
        data = await self._transport.request("GET", f"/attributes/view/{attribute_id}")
        return MISPAttribute.from_misp(data.get("Attribute", data))

    async def search_page(self, query: SearchQuery, page: int, limit: int) -> list[dict[str, Any]]:
        """Fetch one page of raw attribute matches."""
        body = query.to_misp_payload()
        body["page"] = page
        body["limit"] = limit
        data = await self._transport.request("POST", "/attributes/restSearch", json_body=body)
        attributes = data.get("response", {}).get("Attribute", [])
        return list(attributes)

    async def search(self, query: SearchQuery, limit: int = 1000) -> list[dict[str, Any]]:
        """Fetch the first page of raw attribute matches."""
        return await self.search_page(query, page=1, limit=limit)

    def iter_search(
        self,
        query: SearchQuery,
        page_size: int = 1000,
        max_records: int | None = None,
        start_page: int = 1,
        on_warning: WarningCallback | None = None,
    ) -> AsyncIterator[MISPAttribute]:
        """Stream normalized attributes across pages without buffering them all."""

        async def fetch(page: int, limit: int) -> list[dict[str, Any]]:
            return await self.search_page(query, page=page, limit=limit)

        async def iterator() -> AsyncIterator[MISPAttribute]:
            async for raw in paginate(
                fetch,
                page_size=page_size,
                max_records=max_records,
                start_page=start_page,
                on_warning=on_warning,
            ):
                yield MISPAttribute.from_misp(raw)

        return iterator()


class SystemNamespace:
    """Server metadata and capability discovery."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def version(self) -> dict[str, Any]:
        """Return the raw ``/servers/getVersion`` payload."""
        data = await self._transport.request("GET", "/servers/getVersion")
        return dict(data)

    async def capabilities(self) -> set[str]:
        """Discover server capabilities from version metadata."""
        return capabilities_from_version(await self.version())


class ListNamespace:
    """Read-only listing namespace shared by simple MISP resources."""

    def __init__(self, transport: AsyncTransport, path: str) -> None:
        self._transport = transport
        self._path = path

    async def list(self) -> Any:
        """Return the raw resource index."""
        return await self._transport.request("GET", self._path)


class MispClient:
    """Asynchronous client for a single MISP server.

    Usable standalone or as the per-server building block of a fleet::

        async with MispClient(config, api_key="...") as client:
            event = await client.events.get("event-uuid")
    """

    def __init__(
        self,
        config: ServerConfig,
        api_key: str | None = None,
        resolver: CredentialResolver | None = None,
        transport: AsyncTransport | None = None,
    ) -> None:
        self.config = config
        if transport is None:
            key = api_key or (resolver or default_resolver()).resolve(config.credential)
            transport = AsyncTransport(config, key)
        self._transport = transport
        self.events = EventsNamespace(transport)
        self.attributes = AttributesNamespace(transport)
        self.system = SystemNamespace(transport)
        self.objects = ListNamespace(transport, "/objectTemplates")
        self.tags = ListNamespace(transport, "/tags")
        self.taxonomies = ListNamespace(transport, "/taxonomies")
        self.galaxies = ListNamespace(transport, "/galaxies")
        self.warninglists = ListNamespace(transport, "/warninglists")
        self.templates = ListNamespace(transport, "/objectTemplates")
        self.organisations = ListNamespace(transport, "/organisations")
        self.servers = ListNamespace(transport, "/servers")

    async def __aenter__(self) -> MispClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Release the underlying transport."""
        await self._transport.aclose()
