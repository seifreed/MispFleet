"""Reporting namespaces: event reports, analyst data, collections, logs."""

from __future__ import annotations

import builtins
from typing import Any
from urllib.parse import quote

from mispfleet.client.namespaces._base import _as_dict, _as_list, _Namespace, _unwrap


class EventReportsNamespace(_Namespace):
    """Event-report CRUD, restore and import endpoints."""

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the event-report index."""
        data = await self._transport.request("GET", "/eventReports/index")
        return _as_list(data)

    async def get(self, report_id: str) -> dict[str, Any]:
        """Fetch one event report."""
        data = await self._transport.request(
            "GET", f"/eventReports/view/{quote(report_id, safe='')}"
        )
        return _unwrap(data, "EventReport")

    async def add(self, event_id: str, report: dict[str, Any]) -> dict[str, Any]:
        """Create an event report inside an event."""
        data = await self._transport.request(
            "POST",
            f"/eventReports/add/{quote(event_id, safe='')}",
            json_body={"EventReport": report},
            idempotent=False,
        )
        return _unwrap(data, "EventReport")

    async def update(self, report_id: str, report: dict[str, Any]) -> dict[str, Any]:
        """Update an event report."""
        data = await self._transport.request(
            "POST",
            f"/eventReports/edit/{quote(report_id, safe='')}",
            json_body={"EventReport": report},
            idempotent=False,
        )
        return _unwrap(data, "EventReport")

    async def delete(self, report_id: str, hard: bool = False) -> dict[str, Any]:
        """Soft-delete an event report, or hard-delete it permanently."""
        path = f"/eventReports/delete/{quote(report_id, safe='')}"
        if hard:
            path = f"{path}/1"
        data = await self._transport.request("POST", path, idempotent=False)
        return _as_dict(data)

    async def restore(self, report_id: str) -> dict[str, Any]:
        """Restore a soft-deleted event report."""
        data = await self._transport.request(
            "POST", f"/eventReports/restore/{quote(report_id, safe='')}", idempotent=False
        )
        return _unwrap(data, "EventReport")

    async def import_from_url(self, event_id: str, url: str) -> dict[str, Any]:
        """Create an event report by fetching a remote document."""
        data = await self._transport.request(
            "POST",
            f"/eventReports/importReportFromUrl/{quote(event_id, safe='')}",
            json_body={"url": url},
            idempotent=False,
        )
        return _unwrap(data, "EventReport")


class AnalystDataNamespace(_Namespace):
    """Analyst-data (notes, opinions, relationships) endpoints."""

    async def index(self, analyst_type: str) -> builtins.list[dict[str, Any]]:
        """List analyst data of one type (Note, Opinion or Relationship)."""
        data = await self._transport.request(
            "GET", f"/analystData/index/{quote(analyst_type, safe='')}"
        )
        return _as_list(data)

    async def get(self, analyst_type: str, data_id: str) -> dict[str, Any]:
        """Fetch one analyst-data entry."""
        path = f"/analystData/view/{quote(analyst_type, safe='')}/{quote(data_id, safe='')}"
        data = await self._transport.request("GET", path)
        return _as_dict(data)

    async def add(
        self,
        analyst_type: str,
        object_uuid: str,
        object_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Attach analyst data to the given object."""
        path = (
            f"/analystData/add/{quote(analyst_type, safe='')}"
            f"/{quote(object_uuid, safe='')}/{quote(object_type, safe='')}"
        )
        # AddAnalystDataRequest is a oneOf over flat AnalystNote/Opinion/
        # Relationship objects: a model-style {"Note": {...}} wrapper carried
        # none of the fields the server reads.
        data = await self._transport.request("POST", path, json_body=payload, idempotent=False)
        return _as_dict(data)

    async def update(
        self, analyst_type: str, data_id: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Update an analyst-data entry."""
        path = f"/analystData/edit/{quote(analyst_type, safe='')}/{quote(data_id, safe='')}"
        data = await self._transport.request("POST", path, json_body=payload, idempotent=False)
        return _as_dict(data)

    async def delete(self, analyst_type: str, data_id: str) -> dict[str, Any]:
        """Delete an analyst-data entry."""
        path = f"/analystData/delete/{quote(analyst_type, safe='')}/{quote(data_id, safe='')}"
        data = await self._transport.request("DELETE", path, idempotent=False)
        return _as_dict(data)

    async def index_minimal(self, filters: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return a minimal analyst-data index for synchronization.

        MISP answers with an object keyed ``Note``/``Opinion``/
        ``Relationship``, each mapping uuid to timestamp, or with an empty
        array when there is nothing to report. ``list()`` over the object
        returned those three key names and discarded the index itself.
        """
        data = await self._transport.request(
            "POST", "/analystData/indexMinimal", json_body=filters or {}
        )
        return _as_dict(data) if isinstance(data, dict) else {}


class CollectionsNamespace(_Namespace):
    """Collection CRUD endpoints."""

    async def list(self, filter_name: str = "my_collections") -> builtins.list[dict[str, Any]]:
        """Return the collection index for the given filter.

        The endpoint's filter is an enum of my_collections/org_collections;
        the old "all" default was outside it, so the scope a conforming
        server applied was undefined.
        """
        if filter_name not in ("my_collections", "org_collections"):
            raise ValueError(
                f"unknown collection filter {filter_name!r}; "
                "expected 'my_collections' or 'org_collections'"
            )
        # MISP 2.5.44 returns HTTP 500 on an empty request body here; the path
        # already scopes the query, so the body only has to be non-empty.
        data = await self._transport.request(
            "POST",
            f"/collections/index/{quote(filter_name, safe='')}",
            json_body={"filter": filter_name},
        )
        return _as_list(data)

    async def get(self, collection_id: str) -> dict[str, Any]:
        """Fetch one collection."""
        data = await self._transport.request(
            "GET", f"/collections/view/{quote(collection_id, safe='')}"
        )
        return _unwrap(data, "Collection")

    async def add(self, collection: dict[str, Any]) -> dict[str, Any]:
        """Create a collection."""
        data = await self._transport.request(
            "POST", "/collections/add", json_body={"Collection": collection}, idempotent=False
        )
        return _unwrap(data, "Collection")

    async def update(self, collection_id: str, collection: dict[str, Any]) -> dict[str, Any]:
        """Update a collection."""
        data = await self._transport.request(
            "POST",
            f"/collections/edit/{quote(collection_id, safe='')}",
            json_body={"Collection": collection},
            idempotent=False,
        )
        return _unwrap(data, "Collection")

    async def delete(self, collection_id: str) -> dict[str, Any]:
        """Delete a collection."""
        data = await self._transport.request(
            "DELETE", f"/collections/delete/{quote(collection_id, safe='')}", idempotent=False
        )
        return _as_dict(data)


class LogsNamespace(_Namespace):
    """Application-log search endpoint."""

    async def search(self, filters: dict[str, Any] | None = None) -> builtins.list[dict[str, Any]]:
        """Search the application logs (admin only).

        MISP 2.5.44 returns HTTP 500 on an empty request body here, so an
        unfiltered search falls back to an explicit first page rather than the
        ``{}`` that the fake accepted but a real server rejects.
        """
        data = await self._transport.request(
            "POST", "/admin/logs", json_body=filters or {"page": 1}
        )
        return _as_list(data)
