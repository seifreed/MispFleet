"""Server metadata and capability-discovery namespace."""

from __future__ import annotations

from typing import Any

from mispfleet.client.capabilities import capabilities_from_version
from mispfleet.client.namespaces._base import _as_dict, _Namespace


class SystemNamespace(_Namespace):
    """Server metadata and capability discovery."""

    async def version(self) -> dict[str, Any]:
        """Return the raw ``/servers/getVersion`` payload."""
        data = await self._transport.request("GET", "/servers/getVersion")
        return _as_dict(data)

    async def capabilities(self) -> set[str]:
        """Discover server capabilities from version metadata."""
        return capabilities_from_version(await self.version())
