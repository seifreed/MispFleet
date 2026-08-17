"""Shared response-shape helpers and the generic listing namespace."""

from __future__ import annotations

import builtins
from typing import Any

from mispfleet.client.transport import AsyncTransport
from mispfleet.exceptions import ErrorContext, InvalidResponseError


def _as_dict(data: Any, endpoint: str = "") -> dict[str, Any]:
    """Require a JSON object where the MISP API promises one.

    Nothing between the transport and the models checked the shape, so a
    proxy or a non-MISP server answering with an array or a scalar produced a
    raw TypeError or AttributeError instead of the documented typed error.
    """
    if not isinstance(data, dict):
        raise InvalidResponseError(
            f"MISP returned {type(data).__name__} where an object was expected",
            ErrorContext(endpoint=endpoint),
        )
    return data


def _as_list(data: Any, endpoint: str = "") -> builtins.list[Any]:
    """Require a JSON array where the MISP API promises one."""
    if not isinstance(data, list):
        raise InvalidResponseError(
            f"MISP returned {type(data).__name__} where a list was expected",
            ErrorContext(endpoint=endpoint),
        )
    return data


def _unwrap(data: Any, key: str) -> dict[str, Any]:
    """Read MISP's ``{"Key": {...}}`` envelope, tolerating a bare object."""
    payload = _as_dict(data)
    return _as_dict(payload.get(key, payload))


class _Namespace:
    """Base for per-resource namespaces that wrap the shared transport."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport


class ListNamespace(_Namespace):
    """Read-only listing namespace shared by simple MISP resources."""

    def __init__(self, transport: AsyncTransport, path: str) -> None:
        super().__init__(transport)
        self._path = path

    async def list(self) -> Any:
        """Return the raw resource index."""
        return await self._transport.request("GET", self._path)
