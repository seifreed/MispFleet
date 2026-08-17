"""TLS peer-certificate inspection used by health checks."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from datetime import UTC, datetime

from mispfleet.client.transport import build_verify
from mispfleet.models.server import ServerConfig


def _probe_context(config: ServerConfig) -> ssl.SSLContext:
    """Build an SSL context mirroring the server's transport verification."""
    verify = build_verify(config)
    if isinstance(verify, ssl.SSLContext):
        return verify
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


async def peer_certificate_expiry(config: ServerConfig) -> datetime | None:
    """Return the server certificate's ``notAfter`` instant when obtainable.

    Requires an HTTPS URL and a verified handshake; unverified connections
    do not expose the peer certificate, so they yield ``None``.
    """
    if config.url.scheme != "https":
        return None
    host = config.url.host or ""
    port = config.url.port or 443
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=_probe_context(config), server_hostname=host),
            timeout=config.connect_timeout,
        )
    except OSError, ssl.SSLError, TimeoutError:
        return None
    try:
        certificate = writer.get_extra_info("ssl_object").getpeercert() or {}
        not_after = certificate.get("notAfter")
        if not_after is None:
            return None
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(str(not_after)), tz=UTC)
    finally:
        writer.close()
        # Without awaiting the close, a health sweep over many servers leaves
        # half-shut TLS sockets behind until the garbage collector runs.
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()
