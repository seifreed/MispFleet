"""Per-server health and capability checks."""

from __future__ import annotations

import asyncio

from mispfleet.client import MispClient
from mispfleet.client.capabilities import capabilities_from_version
from mispfleet.exceptions import (
    APIError,
    AuthenticationError,
    MispFleetError,
    PermissionDeniedError,
    TLSVerificationError,
)
from mispfleet.fleet.executor import server_error_from
from mispfleet.models.result import ServerHealth


async def check_server(client: MispClient) -> ServerHealth:
    """Probe one server and classify the outcome instead of raising.

    The resulting ``ServerHealth`` distinguishes connectivity, TLS,
    authentication, permission and application failures through the typed
    error kind.
    """
    name = client.config.name
    loop = asyncio.get_running_loop()
    start = loop.time()
    try:
        version = await client.system.version()
    except MispFleetError as error:
        latency = (loop.time() - start) * 1000.0
        reachable = isinstance(error, APIError)
        authenticated = reachable and not isinstance(
            error, AuthenticationError | PermissionDeniedError
        )
        return ServerHealth(
            server=name,
            reachable=reachable,
            authenticated=authenticated,
            read_only=client.config.read_only,
            latency_ms=latency if reachable else None,
            tls_valid=False if isinstance(error, TLSVerificationError) else None,
            error=server_error_from(name, error),
        )
    latency = (loop.time() - start) * 1000.0
    warnings: list[str] = []
    if not client.config.verify_tls:
        warnings.append("TLS verification is disabled for this server")
    return ServerHealth(
        server=name,
        reachable=True,
        authenticated=True,
        read_only=client.config.read_only,
        latency_ms=latency,
        misp_version=str(version.get("version")) if version.get("version") else None,
        api_version=str(version.get("pymisp_recommended_version") or "") or None,
        tls_valid=True if client.config.url.scheme == "https" else None,
        capabilities=capabilities_from_version(version),
        warnings=warnings,
    )
