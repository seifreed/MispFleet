"""Minimal OpenCTI GraphQL client for pushing STIX bundles.

Uses httpx directly rather than depending on ``pycti``. The bearer token is
never included in error messages or logs.
"""

from __future__ import annotations

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
    MispServerError,
    RequestTimeoutError,
)

_ABOUT_QUERY = "query { about { version } }"

_PUSH_MUTATION = "mutation StixBundlePush($bundle: String!) { " "stixBundlePush(bundle: $bundle) }"


def _error_messages(errors: Any) -> str:
    """Summarize a GraphQL ``errors`` payload of any shape.

    A proxy answering with a bare string would otherwise be iterated character
    by character and raise an untyped ``AttributeError``.
    """
    if not isinstance(errors, list):
        return str(errors)
    return "; ".join(
        str(item.get("message", item)) if isinstance(item, dict) else str(item) for item in errors
    )


def _field(data: Any, *path: str) -> str:
    """Read a nested GraphQL field, refusing to guess when the shape differs."""
    current: Any = data
    for key in path:
        if not isinstance(current, dict) or key not in current:
            raise InvalidResponseError(
                f"OpenCTI response is missing {'.'.join(path)}",
                ErrorContext(endpoint="/graphql"),
            )
        current = current[key]
    return str(current)


class OpenCTIClient:
    """Talks to an OpenCTI instance over its GraphQL API."""

    def __init__(self, url: str, token: str, timeout: float = 30.0) -> None:
        self._client = httpx.AsyncClient(
            base_url=url.rstrip("/"),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            timeout=timeout,
            follow_redirects=False,
        )

    async def _graphql(self, query: str, variables: dict[str, Any] | None = None) -> Any:
        payload = {"query": query, "variables": variables or {}}
        try:
            response = await self._client.post("/graphql", content=json.dumps(payload))
        except httpx.TimeoutException as error:
            raise RequestTimeoutError(
                "OpenCTI request timed out", ErrorContext(endpoint="/graphql", retryable=True)
            ) from error
        except httpx.HTTPError as error:
            raise ConnectionFailedError(
                f"OpenCTI connection failed: {type(error).__name__}",
                ErrorContext(endpoint="/graphql", retryable=True),
            ) from error
        if response.status_code == 401:
            raise AuthenticationError(
                "OpenCTI rejected the token",
                ErrorContext(endpoint="/graphql", status_code=401),
            )
        if response.status_code >= 500:
            raise MispServerError(
                f"OpenCTI returned HTTP {response.status_code}",
                ErrorContext(endpoint="/graphql", status_code=response.status_code),
            )
        try:
            body = response.json()
        except ValueError as error:
            raise InvalidResponseError(
                "OpenCTI returned a non-JSON response",
                ErrorContext(endpoint="/graphql", status_code=response.status_code),
            ) from error
        if not isinstance(body, dict):
            raise InvalidResponseError(
                "OpenCTI returned a JSON document that is not an object",
                ErrorContext(endpoint="/graphql", status_code=response.status_code),
            )
        if body.get("errors"):
            messages = _error_messages(body["errors"])
            raise APIError(
                f"OpenCTI GraphQL error: {messages}",
                ErrorContext(endpoint="/graphql", status_code=response.status_code),
            )
        return body.get("data", {})

    async def version(self) -> str:
        """Return the OpenCTI platform version."""
        data = await self._graphql(_ABOUT_QUERY)
        return _field(data, "about", "version")

    async def push_bundle(self, bundle: dict[str, Any]) -> str:
        """Import a STIX bundle; returns the OpenCTI work identifier."""
        data = await self._graphql(_PUSH_MUTATION, {"bundle": json.dumps(bundle)})
        return _field(data, "stixBundlePush")

    async def __aenter__(self) -> OpenCTIClient:
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
