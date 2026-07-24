"""Minimal TAXII 2.1 client for pushing STIX bundles to collections."""

from __future__ import annotations

import base64
import json
from types import TracebackType
from typing import Any

import httpx

from mispfleet.exceptions import (
    APIError,
    AuthenticationError,
    ConnectionFailedError,
    ErrorContext,
    InvalidResponseError,
    MispFleetError,
    NotFoundError,
    PermissionDeniedError,
    RequestTimeoutError,
)

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"


class TaxiiClient:
    """Talks TAXII 2.1: discovery, collection listing and object push."""

    def __init__(
        self,
        url: str,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        headers = {"Accept": TAXII_MEDIA_TYPE}
        if username is not None:
            digest = base64.b64encode(f"{username}:{password or ''}".encode()).decode()
            headers["Authorization"] = f"Basic {digest}"
        elif token is not None:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(
            base_url=url.rstrip("/"),
            headers=headers,
            timeout=timeout,
            follow_redirects=False,
        )

    async def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        try:
            response = await self._client.request(
                method,
                path,
                content=json.dumps(body) if body is not None else None,
                headers={"Content-Type": TAXII_MEDIA_TYPE} if body is not None else {},
            )
        except httpx.TimeoutException as error:
            raise RequestTimeoutError(
                "TAXII request timed out", ErrorContext(endpoint=path, retryable=True)
            ) from error
        except httpx.HTTPError as error:
            raise ConnectionFailedError(
                f"TAXII connection failed: {type(error).__name__}",
                ErrorContext(endpoint=path, retryable=True),
            ) from error
        if not response.is_success:
            raise self._status_error(response, path)
        try:
            return response.json()
        except ValueError as error:
            raise InvalidResponseError(
                "TAXII server returned a non-JSON response",
                ErrorContext(endpoint=path, status_code=response.status_code),
            ) from error

    def _status_error(self, response: httpx.Response, path: str) -> MispFleetError:
        context = ErrorContext(endpoint=path, status_code=response.status_code)
        message = f"TAXII server returned HTTP {response.status_code} for {path}"
        if response.status_code == 401:
            return AuthenticationError(message, context)
        if response.status_code == 403:
            return PermissionDeniedError(message, context)
        if response.status_code == 404:
            return NotFoundError(message, context)
        return APIError(message, context)

    async def discovery(self) -> dict[str, Any]:
        """Return the TAXII discovery document."""
        return dict(await self._request("GET", "/taxii2/"))

    async def collections(self, api_root: str) -> list[dict[str, Any]]:
        """List collections under an API root."""
        data = await self._request("GET", f"/{api_root.strip('/')}/collections/")
        return list(data.get("collections", []))

    async def push(
        self,
        api_root: str,
        collection_id: str,
        objects: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Add STIX objects to a collection; returns the TAXII status."""
        data = await self._request(
            "POST",
            f"/{api_root.strip('/')}/collections/{collection_id}/objects/",
            body={"objects": objects},
        )
        return dict(data)

    async def __aenter__(self) -> TaxiiClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Release the connection pool."""
        await self._client.aclose()
