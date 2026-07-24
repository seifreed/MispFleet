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
        if body.get("errors"):
            messages = "; ".join(str(item.get("message", "")) for item in body["errors"])
            raise APIError(
                f"OpenCTI GraphQL error: {messages}",
                ErrorContext(endpoint="/graphql", status_code=response.status_code),
            )
        return body.get("data", {})

    async def version(self) -> str:
        """Return the OpenCTI platform version."""
        data = await self._graphql(_ABOUT_QUERY)
        return str(data["about"]["version"])

    async def push_bundle(self, bundle: dict[str, Any]) -> str:
        """Import a STIX bundle; returns the OpenCTI work identifier."""
        data = await self._graphql(_PUSH_MUTATION, {"bundle": json.dumps(bundle)})
        return str(data["stixBundlePush"])

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
