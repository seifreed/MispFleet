"""Threat-content namespaces: events, attributes, objects, sightings, tags."""

from __future__ import annotations

import builtins
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote

from mispfleet.client.namespaces._base import _as_dict, _as_list, _Namespace, _unwrap
from mispfleet.client.pagination import WarningCallback, paginate
from mispfleet.models.attribute import MISPAttribute, MISPObject
from mispfleet.models.event import MISPEvent, Sighting
from mispfleet.models.query import SearchQuery


class EventsNamespace(_Namespace):
    """Event retrieval and mutation endpoints."""

    async def get(self, event_id: str) -> MISPEvent:
        """Fetch one event by UUID or numeric identifier."""
        data = await self._transport.request("GET", f"/events/view/{quote(event_id, safe='')}")
        return MISPEvent.from_misp(data)

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the plain event index."""
        data = await self._transport.request("GET", "/events")
        return _as_list(data)

    async def index(self, tags: set[str] | None = None) -> builtins.list[dict[str, Any]]:
        """List event metadata, optionally filtered by event tags."""
        body: dict[str, Any] = {}
        if tags:
            body["tags"] = sorted(tags)
        data = await self._transport.request("POST", "/events/index", json_body=body)
        return _as_list(data)

    async def add(self, event: MISPEvent) -> MISPEvent:
        """Create a new event; never retried because creation is not idempotent."""
        data = await self._transport.request(
            "POST", "/events/add", json_body={"Event": event.to_misp()}, idempotent=False
        )
        return MISPEvent.from_misp(data)

    async def update(self, event: MISPEvent) -> MISPEvent:
        """Update an existing event identified by its UUID."""
        data = await self._transport.request(
            "PUT",
            f"/events/edit/{quote(event.uuid, safe='')}",
            json_body={"Event": event.to_misp()},
            idempotent=False,
        )
        return MISPEvent.from_misp(data)

    async def search(self, query: SearchQuery, limit: int = 1000) -> builtins.list[MISPEvent]:
        """Search events through ``/events/restSearch``."""
        body = query.event_payload()
        if query.limit_per_server is not None:
            limit = min(limit, query.limit_per_server)
        body["limit"] = limit
        data = await self._transport.request("POST", "/events/restSearch", json_body=body)
        return [
            MISPEvent.from_misp(item)
            for item in _as_list(_as_dict(data, "/events/restSearch").get("response", []))
            if query.matches_locally(item)
        ]

    async def delete(self, event_id: str) -> dict[str, Any]:
        """Delete an event by UUID or numeric identifier."""
        data = await self._transport.request(
            "DELETE", f"/events/delete/{quote(event_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def publish(self, event_id: str) -> dict[str, Any]:
        """Publish an event."""
        data = await self._transport.request(
            "POST", f"/events/publish/{quote(event_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def unpublish(self, event_id: str) -> dict[str, Any]:
        """Unpublish an event."""
        data = await self._transport.request(
            "POST", f"/events/unpublish/{quote(event_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def add_tag(self, event_id: str, tag: str, local: bool = False) -> dict[str, Any]:
        """Attach a tag (by name or id) to an event."""
        path = (
            f"/events/addTag/{quote(event_id, safe='')}"
            f"/{quote(tag, safe='')}/local:{1 if local else 0}"
        )
        data = await self._transport.request("POST", path, idempotent=False)
        return _as_dict(data)

    async def remove_tag(self, event_id: str, tag: str) -> dict[str, Any]:
        """Detach a tag (by name or id) from an event."""
        path = f"/events/removeTag/{quote(event_id, safe='')}/{quote(tag, safe='')}"
        data = await self._transport.request("POST", path, idempotent=False)
        return _as_dict(data)

    async def enrich(self, event_id: str, modules: builtins.list[str]) -> dict[str, Any]:
        """Run the given enrichment modules over an event."""
        data = await self._transport.request(
            "POST",
            f"/events/enrichEvent/{quote(event_id, safe='')}",
            json_body=dict.fromkeys(modules, 1),
            idempotent=False,
        )
        return _as_dict(data)


class AttributesNamespace(_Namespace):
    """Attribute search endpoints."""

    async def get(self, attribute_id: str) -> MISPAttribute:
        """Fetch one attribute by UUID or numeric id."""
        data = await self._transport.request(
            "GET", f"/attributes/view/{quote(attribute_id, safe='')}"
        )
        return MISPAttribute.from_misp(_as_dict(data).get("Attribute", data))

    async def list(self) -> builtins.list[MISPAttribute]:
        """List attributes through the plain ``/attributes`` index."""
        data = await self._transport.request("GET", "/attributes")
        return [MISPAttribute.from_misp(item.get("Attribute", item)) for item in _as_list(data)]

    async def add(self, event_id: str, attribute: MISPAttribute) -> MISPAttribute:
        """Create an attribute inside an event."""
        data = await self._transport.request(
            "POST",
            f"/attributes/add/{quote(event_id, safe='')}",
            json_body=attribute.to_misp(),
            idempotent=False,
        )
        return MISPAttribute.from_misp(_as_dict(data).get("Attribute", data))

    async def update(self, attribute: MISPAttribute) -> MISPAttribute:
        """Update an existing attribute identified by its UUID."""
        data = await self._transport.request(
            "PUT",
            f"/attributes/edit/{quote(attribute.uuid or '', safe='')}",
            json_body=attribute.to_misp(),
            idempotent=False,
        )
        return MISPAttribute.from_misp(_as_dict(data).get("Attribute", data))

    async def delete(self, attribute_id: str) -> dict[str, Any]:
        """Soft-delete an attribute."""
        data = await self._transport.request(
            "DELETE", f"/attributes/delete/{quote(attribute_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def restore(self, attribute_id: str) -> MISPAttribute:
        """Restore a soft-deleted attribute."""
        data = await self._transport.request(
            "POST", f"/attributes/restore/{quote(attribute_id, safe='')}", idempotent=False
        )
        return MISPAttribute.from_misp(_as_dict(data).get("Attribute", data))

    async def add_tag(self, attribute_id: str, tag: str, local: bool = False) -> dict[str, Any]:
        """Attach a tag (by name or id) to an attribute."""
        path = (
            f"/attributes/addTag/{quote(attribute_id, safe='')}"
            f"/{quote(tag, safe='')}/local:{1 if local else 0}"
        )
        data = await self._transport.request("POST", path, idempotent=False)
        return _as_dict(data)

    async def remove_tag(self, attribute_id: str, tag: str) -> dict[str, Any]:
        """Detach a tag (by name or id) from an attribute."""
        path = f"/attributes/removeTag/{quote(attribute_id, safe='')}/{quote(tag, safe='')}"
        data = await self._transport.request("POST", path, idempotent=False)
        return _as_dict(data)

    async def describe_types(self) -> dict[str, Any]:
        """Return the server's attribute type taxonomy."""
        data = await self._transport.request("GET", "/attributes/describeTypes")
        return _unwrap(data, "result")

    async def statistics(self, context: str = "type", percentage: bool = False) -> dict[str, Any]:
        """Return attribute statistics grouped by type or category."""
        path = f"/attributes/attributeStatistics/{quote(context, safe='')}/{1 if percentage else 0}"
        data = await self._transport.request("GET", path)
        return _as_dict(data)

    async def by_base64_value(self, base64_value: str) -> builtins.list[MISPAttribute]:
        """Look attributes up by their base64-encoded value."""
        data = await self._transport.request(
            "GET", f"/attributes/getAttributeByB64Value/{quote(base64_value, safe='')}"
        )
        return [MISPAttribute.from_misp(item.get("Attribute", item)) for item in _as_list(data)]

    async def enrich(self, attribute_id: str, modules: builtins.list[str]) -> dict[str, Any]:
        """Run the given enrichment modules over an attribute."""
        data = await self._transport.request(
            "POST",
            f"/attributes/enrich/{quote(attribute_id, safe='')}",
            json_body=dict.fromkeys(modules, 1),
            idempotent=False,
        )
        return _as_dict(data)

    async def search_page(
        self, query: SearchQuery, page: int, limit: int
    ) -> builtins.list[dict[str, Any]]:
        """Fetch one page of raw attribute matches."""
        body = query.attribute_payload()
        body["page"] = page
        body["limit"] = limit
        data = await self._transport.request("POST", "/attributes/restSearch", json_body=body)
        envelope = _as_dict(data, "/attributes/restSearch")
        attributes = _as_dict(envelope.get("response", {}), "/attributes/restSearch")
        return _as_list(attributes.get("Attribute", []), "/attributes/restSearch")

    async def search(self, query: SearchQuery, limit: int = 1000) -> builtins.list[dict[str, Any]]:
        """Fetch the first page of raw attribute matches."""
        if query.limit_per_server is not None:
            limit = min(limit, query.limit_per_server)
        page = await self.search_page(query, page=1, limit=limit)
        # Filtered here, not in search_page: a short filtered page would make
        # paginate believe the dataset ended.
        return [raw for raw in page if query.matches_locally(raw)]

    def iter_search(
        self,
        query: SearchQuery,
        page_size: int = 1000,
        max_records: int | None = None,
        start_page: int = 1,
        on_warning: WarningCallback | None = None,
    ) -> AsyncIterator[MISPAttribute]:
        """Stream normalized attributes across pages without buffering them all."""
        if max_records is None:
            max_records = query.limit_per_server

        async def fetch(page: int, limit: int) -> builtins.list[dict[str, Any]]:
            return await self.search_page(query, page=page, limit=limit)

        async def iterator() -> AsyncIterator[MISPAttribute]:
            # The cap counts records the caller actually receives: letting
            # paginate apply it counted the ones the local filter then dropped,
            # so a scoped query returned a fraction of limit_per_server.
            kept = 0
            async for raw in paginate(
                fetch,
                page_size=page_size,
                max_records=None,
                start_page=start_page,
                on_warning=on_warning,
            ):
                if not query.matches_locally(raw):
                    continue
                yield MISPAttribute.from_misp(raw)
                kept += 1
                if max_records is not None and kept >= max_records:
                    return

        return iterator()


class TagsNamespace(_Namespace):
    """Tag listing, lookup and mutation endpoints."""

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the raw tag index."""
        data = await self._transport.request("GET", "/tags")
        return _as_list(_as_dict(data).get("Tag", data) if isinstance(data, dict) else data)

    async def get(self, tag_id: str) -> dict[str, Any]:
        """Fetch one tag by id."""
        data = await self._transport.request("GET", f"/tags/view/{quote(tag_id, safe='')}")
        return _unwrap(data, "Tag")

    async def add(self, tag: dict[str, Any]) -> dict[str, Any]:
        """Create a tag from a raw MISP tag payload (``name`` plus options)."""
        data = await self._transport.request(
            "POST", "/tags/add", json_body={"Tag": tag}, idempotent=False
        )
        return _unwrap(data, "Tag")

    async def update(self, tag_id: str, tag: dict[str, Any]) -> dict[str, Any]:
        """Update an existing tag."""
        data = await self._transport.request(
            "POST", f"/tags/edit/{quote(tag_id, safe='')}", json_body={"Tag": tag}, idempotent=False
        )
        return _unwrap(data, "Tag")

    async def delete(self, tag_id: str) -> dict[str, Any]:
        """Delete a tag."""
        data = await self._transport.request(
            "POST", f"/tags/delete/{quote(tag_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def search(self, term: str) -> builtins.list[dict[str, Any]]:
        """Search tags by substring."""
        data = await self._transport.request("GET", f"/tags/search/{quote(term, safe='')}")
        return _as_list(data)


class SightingsNamespace(_Namespace):
    """Sighting listing and mutation endpoints."""

    async def index(self, event_id: str) -> builtins.list[Sighting]:
        """List the sightings recorded for one event.

        The endpoint matches on the numeric event id only. Handed a UUID it
        answers with an empty array rather than an error, so every UUID-based
        lookup silently reported that the event had no sightings at all.
        """
        identifier = event_id
        if not identifier.isdigit():
            event = await self._transport.request("GET", f"/events/view/{quote(event_id, safe='')}")
            identifier = str(_unwrap(event, "Event").get("id", event_id))
        data = await self._transport.request(
            "GET", f"/sightings/index/{quote(identifier, safe='')}"
        )
        return [Sighting.from_misp(_unwrap(item, "Sighting")) for item in _as_list(data)]

    async def add(self, value: str, source: str = "", sighting_type: str = "0") -> dict[str, Any]:
        """Record a sighting for every attribute matching ``value``."""
        # `values` is the array the endpoint reads; `value` alone is dropped as
        # an unknown key, so every sighting was silently discarded.
        body = {"values": [value], "source": source, "type": sighting_type}
        data = await self._transport.request(
            "POST", "/sightings/add", json_body=body, idempotent=False
        )
        return _as_dict(data)

    async def add_to_attribute(self, attribute_id: str) -> dict[str, Any]:
        """Record a sighting directly on one attribute."""
        data = await self._transport.request(
            "POST", f"/sightings/add/{quote(attribute_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def delete(self, sighting_id: str) -> dict[str, Any]:
        """Delete a sighting."""
        data = await self._transport.request(
            "POST", f"/sightings/delete/{quote(sighting_id, safe='')}", idempotent=False
        )
        return _as_dict(data)


class ObjectsNamespace(_Namespace):
    """MISP object search, lookup and mutation endpoints."""

    async def search(self, query: SearchQuery, limit: int = 1000) -> builtins.list[MISPObject]:
        """Search objects through ``/objects/restsearch``."""
        body = query.object_payload()
        if query.limit_per_server is not None:
            limit = min(limit, query.limit_per_server)
        body["limit"] = limit
        data = await self._transport.request("POST", "/objects/restsearch", json_body=body)
        return [
            MISPObject.from_misp(_unwrap(item, "Object"))
            for item in _as_list(_as_dict(data, "/objects/restsearch").get("response", []))
        ]

    async def get(self, object_id: str) -> MISPObject:
        """Fetch one object by UUID or numeric id."""
        data = await self._transport.request("GET", f"/objects/view/{quote(object_id, safe='')}")
        return MISPObject.from_misp(_as_dict(data).get("Object", data))

    async def add(self, event_id: str, template_id: str, obj: MISPObject) -> MISPObject:
        """Create an object inside an event from a template."""
        path = f"/objects/add/{quote(event_id, safe='')}/{quote(template_id, safe='')}"
        data = await self._transport.request(
            "POST", path, json_body=obj.to_misp(), idempotent=False
        )
        return MISPObject.from_misp(_as_dict(data).get("Object", data))

    async def delete(self, object_id: str, hard: bool = False) -> dict[str, Any]:
        """Delete an object, optionally hard-deleting it."""
        path = f"/objects/delete/{quote(object_id, safe='')}/{1 if hard else 0}"
        data = await self._transport.request("DELETE", path, idempotent=False)
        return _as_dict(data)
