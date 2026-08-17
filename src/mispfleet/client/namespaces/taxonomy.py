"""Taxonomy namespaces: taxonomies, warninglists, noticelists, galaxies."""

from __future__ import annotations

import builtins
from typing import Any
from urllib.parse import quote

from mispfleet.client.namespaces._base import _as_dict, _as_list, _Namespace


class TaxonomiesNamespace(_Namespace):
    """Taxonomy listing, activation and export endpoints."""

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the raw taxonomy index."""
        data = await self._transport.request("GET", "/taxonomies")
        return _as_list(data)

    async def get(self, taxonomy_id: str) -> dict[str, Any]:
        """Fetch one taxonomy with its predicates."""
        data = await self._transport.request(
            "GET", f"/taxonomies/view/{quote(taxonomy_id, safe='')}"
        )
        return _as_dict(data)

    async def enable(self, taxonomy_id: str) -> dict[str, Any]:
        """Enable a taxonomy."""
        data = await self._transport.request(
            "POST", f"/taxonomies/enable/{quote(taxonomy_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def disable(self, taxonomy_id: str) -> dict[str, Any]:
        """Disable a taxonomy."""
        data = await self._transport.request(
            "POST", f"/taxonomies/disable/{quote(taxonomy_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def update(self) -> dict[str, Any]:
        """Update the taxonomy library from the bundled definitions."""
        data = await self._transport.request("POST", "/taxonomies/update", idempotent=False)
        return _as_dict(data)

    async def tags(self, taxonomy_id: str) -> builtins.list[dict[str, Any]]:
        """List the tags a taxonomy can generate."""
        data = await self._transport.request(
            "GET", f"/taxonomies/taxonomy_tags/{quote(taxonomy_id, safe='')}"
        )
        return list(_as_dict(data).get("entries", []))

    async def export(self, taxonomy_id: str) -> dict[str, Any]:
        """Export one taxonomy in machinetag JSON form."""
        data = await self._transport.request(
            "GET", f"/taxonomies/export/{quote(taxonomy_id, safe='')}"
        )
        return _as_dict(data)


class WarninglistsNamespace(_Namespace):
    """Warninglist listing, activation and value-check endpoints."""

    async def list(self, value: str | None = None) -> builtins.list[dict[str, Any]]:
        """Return the warninglist index, optionally filtered by value."""
        if value is None:
            data = await self._transport.request("GET", "/warninglists")
        else:
            data = await self._transport.request(
                "POST", "/warninglists", json_body={"value": value}
            )
        return _as_list(
            _as_dict(data).get("Warninglists", data) if isinstance(data, dict) else data
        )

    async def get(self, warninglist_id: str) -> dict[str, Any]:
        """Fetch one warninglist with its entries."""
        data = await self._transport.request(
            "GET", f"/warninglists/view/{quote(warninglist_id, safe='')}"
        )
        return _as_dict(data)

    async def toggle(self, warninglist_ids: builtins.list[str], enabled: bool) -> dict[str, Any]:
        """Enable or disable the given warninglists."""
        body = {"id": warninglist_ids, "enabled": enabled}
        data = await self._transport.request(
            "POST", "/warninglists/toggleEnable", json_body=body, idempotent=False
        )
        return _as_dict(data)

    async def check_value(self, values: builtins.list[str]) -> dict[str, Any]:
        """Check which enabled warninglists match each of the given values.

        The response maps each matched value to its warninglists, but MISP is
        PHP: an empty result is ``json_encode([])`` — a JSON array, not an
        object — so reading it as a mapping raised on the common no-match case.
        """
        data = await self._transport.request("POST", "/warninglists/checkValue", json_body=values)
        if isinstance(data, list) and not data:
            return {}
        return _as_dict(data)

    async def update(self) -> dict[str, Any]:
        """Update the warninglist library from the bundled definitions."""
        data = await self._transport.request("POST", "/warninglists/update", idempotent=False)
        return _as_dict(data)


class NoticelistsNamespace(_Namespace):
    """Noticelist listing and activation endpoints."""

    async def list(self) -> builtins.list[dict[str, Any]]:
        """Return the raw noticelist index."""
        data = await self._transport.request("GET", "/noticelists")
        return _as_list(data)

    async def get(self, noticelist_id: str) -> dict[str, Any]:
        """Fetch one noticelist with its entries."""
        data = await self._transport.request(
            "GET", f"/noticelists/view/{quote(noticelist_id, safe='')}"
        )
        return _as_dict(data)

    async def toggle(self, noticelist_id: str) -> dict[str, Any]:
        """Toggle one noticelist between enabled and disabled."""
        data = await self._transport.request(
            "POST", f"/noticelists/toggleEnable/{quote(noticelist_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def update(self) -> dict[str, Any]:
        """Update the noticelist library from the bundled definitions."""
        data = await self._transport.request("POST", "/noticelists/update", idempotent=False)
        return _as_dict(data)


class GalaxiesNamespace(_Namespace):
    """Galaxy listing, import/export and cluster-attachment endpoints."""

    async def list(self, search: str | None = None) -> builtins.list[dict[str, Any]]:
        """Return the galaxy index, optionally filtered by a search term."""
        if search is None:
            data = await self._transport.request("GET", "/galaxies")
        else:
            data = await self._transport.request("POST", "/galaxies", json_body={"value": search})
        return _as_list(data)

    async def get(self, galaxy_id: str) -> dict[str, Any]:
        """Fetch one galaxy with its clusters."""
        data = await self._transport.request("GET", f"/galaxies/view/{quote(galaxy_id, safe='')}")
        return _as_dict(data)

    async def update(self) -> dict[str, Any]:
        """Update the galaxy library from the bundled definitions."""
        data = await self._transport.request("POST", "/galaxies/update", idempotent=False)
        return _as_dict(data)

    async def delete(self, galaxy_id: str) -> dict[str, Any]:
        """Delete a galaxy."""
        data = await self._transport.request(
            "DELETE", f"/galaxies/delete/{quote(galaxy_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def import_clusters(self, clusters: builtins.list[dict[str, Any]]) -> dict[str, Any]:
        """Import galaxy clusters from their exported JSON form."""
        data = await self._transport.request(
            "POST", "/galaxies/import", json_body=clusters, idempotent=False
        )
        return _as_dict(data)

    async def export(self, galaxy_id: str) -> builtins.list[dict[str, Any]]:
        """Export one galaxy's clusters."""
        data = await self._transport.request(
            "POST",
            f"/galaxies/export/{quote(galaxy_id, safe='')}",
            # Verified against MISP 2.5.44: without a distribution filter the
            # endpoint returns nothing, exactly as it does with neither flag.
            json_body={
                "Galaxy": {
                    "default": True,
                    "custom": True,
                    "distribution": [0, 1, 2, 3, 4],
                }
            },
        )
        return _as_list(data)

    async def attach_cluster(
        self,
        target_id: str,
        target_type: str,
        cluster_id: str,
        local: bool = False,
    ) -> dict[str, Any]:
        """Attach a galaxy cluster to an event, attribute or tag collection."""
        path = (
            f"/galaxies/attachCluster/{quote(target_id, safe='')}"
            f"/{quote(target_type, safe='')}/local:{1 if local else 0}"
        )
        data = await self._transport.request(
            "POST", path, json_body={"Galaxy": {"target_id": cluster_id}}, idempotent=False
        )
        return _as_dict(data)


class GalaxyClustersNamespace(_Namespace):
    """Galaxy-cluster CRUD, publication and restore endpoints."""

    async def index(
        self, galaxy_id: str, search: str | None = None
    ) -> builtins.list[dict[str, Any]]:
        """List the clusters of one galaxy, optionally filtered."""
        path = f"/galaxy_clusters/index/{quote(galaxy_id, safe='')}"
        if search is None:
            data = await self._transport.request("GET", path)
        else:
            data = await self._transport.request(
                "POST", path, json_body={"context": "all", "searchall": search}
            )
        return _as_list(data)

    async def get(self, cluster_id: str) -> dict[str, Any]:
        """Fetch one galaxy cluster."""
        data = await self._transport.request(
            "GET", f"/galaxy_clusters/view/{quote(cluster_id, safe='')}"
        )
        return _as_dict(data)

    async def add(self, galaxy_id: str, cluster: dict[str, Any]) -> dict[str, Any]:
        """Create a cluster inside a galaxy."""
        data = await self._transport.request(
            "POST",
            f"/galaxy_clusters/add/{quote(galaxy_id, safe='')}",
            json_body={"GalaxyCluster": cluster},
            idempotent=False,
        )
        return _as_dict(data)

    async def update(self, cluster_id: str, cluster: dict[str, Any]) -> dict[str, Any]:
        """Update an existing cluster."""
        data = await self._transport.request(
            "PUT",
            f"/galaxy_clusters/edit/{quote(cluster_id, safe='')}",
            json_body={"GalaxyCluster": cluster},
            idempotent=False,
        )
        return _as_dict(data)

    async def publish(self, cluster_id: str) -> dict[str, Any]:
        """Publish a cluster."""
        data = await self._transport.request(
            "POST", f"/galaxy_clusters/publish/{quote(cluster_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def unpublish(self, cluster_id: str) -> dict[str, Any]:
        """Unpublish a cluster."""
        data = await self._transport.request(
            "POST", f"/galaxy_clusters/unpublish/{quote(cluster_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def delete(self, cluster_id: str) -> dict[str, Any]:
        """Soft-delete a cluster."""
        data = await self._transport.request(
            "POST", f"/galaxy_clusters/delete/{quote(cluster_id, safe='')}", idempotent=False
        )
        return _as_dict(data)

    async def restore(self, cluster_id: str) -> dict[str, Any]:
        """Restore a soft-deleted cluster."""
        data = await self._transport.request(
            "POST", f"/galaxy_clusters/restore/{quote(cluster_id, safe='')}", idempotent=False
        )
        return _as_dict(data)
