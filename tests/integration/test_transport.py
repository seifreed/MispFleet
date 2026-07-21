"""Integration tests for the HTTP transport against a real local server."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import certifi
import pytest
from pydantic import AnyHttpUrl

from mispfleet.client.transport import AsyncTransport
from mispfleet.exceptions import (
    APIError,
    AuthenticationError,
    ConflictError,
    ConnectionFailedError,
    InvalidResponseError,
    MispServerError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    RequestTimeoutError,
    ResponseTooLargeError,
    TLSVerificationError,
    ValidationError,
)
from mispfleet.models.server import CredentialReference, RetryConfig, ServerConfig
from tests.conftest import config_for
from tests.fake_misp import API_KEY, FakeMisp
from tests.support import contains, eq, not_contains, ok

FIXTURES = Path(__file__).parent.parent / "fixtures"


def transport_for(app: FakeMisp, **overrides: Any) -> AsyncTransport:
    return AsyncTransport(config_for(app, **overrides), API_KEY)


async def test_successful_request_returns_parsed_json(fake_misp: FakeMisp) -> None:
    transport = transport_for(fake_misp)
    try:
        data = await transport.request("GET", "/servers/getVersion")
        eq(data["version"], "2.4.190")
        eq(transport.server_name, "test-server")
    finally:
        await transport.aclose()


async def test_status_codes_map_to_typed_exceptions(fake_misp: FakeMisp) -> None:
    cases: list[tuple[int, type[Exception]]] = [
        (400, ValidationError),
        (401, AuthenticationError),
        (403, PermissionDeniedError),
        (404, NotFoundError),
        (409, ConflictError),
        (418, APIError),
        (422, ValidationError),
        (500, MispServerError),
        (302, InvalidResponseError),
    ]
    transport = transport_for(fake_misp)
    try:
        for status, exception_type in cases:
            fake_misp.script(status, '{"message": "scripted"}')
            with pytest.raises(exception_type) as excinfo:
                await transport.request("GET", "/servers/getVersion")
            error = excinfo.value
            if isinstance(error, APIError) and status not in (302,):
                eq(error.context.status_code, status)
    finally:
        await transport.aclose()


async def test_retry_recovers_from_transient_failures(fake_misp: FakeMisp) -> None:
    fake_misp.script(503, '{"message": "unavailable"}')
    fake_misp.script(502, '{"message": "bad gateway"}')
    transport = transport_for(
        fake_misp,
        retry={"max_attempts": 3, "initial_delay": 0.0, "jitter": False},
    )
    try:
        data = await transport.request("GET", "/servers/getVersion")
        eq(data["version"], "2.4.190")
        eq(len(fake_misp.requests_seen), 3)
    finally:
        await transport.aclose()


async def test_retry_gives_up_after_max_attempts(fake_misp: FakeMisp) -> None:
    for _ in range(2):
        fake_misp.script(503, '{"message": "unavailable"}')
    transport = transport_for(
        fake_misp,
        retry={"max_attempts": 2, "initial_delay": 0.0, "jitter": False},
    )
    try:
        with pytest.raises(MispServerError) as excinfo:
            await transport.request("GET", "/servers/getVersion")
        ok(excinfo.value.context.retryable)
    finally:
        await transport.aclose()


async def test_retry_respects_retry_after_header_and_jitter(fake_misp: FakeMisp) -> None:
    fake_misp.script(429, '{"message": "slow down"}', {"Retry-After": "0"})
    transport = transport_for(
        fake_misp,
        retry={"max_attempts": 2, "initial_delay": 0.001, "jitter": True},
    )
    try:
        data = await transport.request("GET", "/servers/getVersion")
        eq(data["version"], "2.4.190")
    finally:
        await transport.aclose()


async def test_rate_limit_error_without_retry_after(fake_misp: FakeMisp) -> None:
    fake_misp.script(429, '{"message": "slow down"}')
    transport = transport_for(fake_misp)
    try:
        with pytest.raises(RateLimitError) as excinfo:
            await transport.request("GET", "/servers/getVersion")
        eq(excinfo.value.retry_after, None)
    finally:
        await transport.aclose()


async def test_non_idempotent_requests_are_never_retried(fake_misp: FakeMisp) -> None:
    fake_misp.script(503, '{"message": "unavailable"}')
    transport = transport_for(
        fake_misp,
        retry={"max_attempts": 4, "initial_delay": 0.0, "jitter": False},
    )
    try:
        with pytest.raises(MispServerError):
            await transport.request("POST", "/events/add", json_body={}, idempotent=False)
        eq(len(fake_misp.requests_seen), 1)
    finally:
        await transport.aclose()


async def test_timeout_maps_to_request_timeout_error(fake_misp: FakeMisp) -> None:
    fake_misp.delay = 0.3
    transport = transport_for(fake_misp, request_timeout=0.05)
    try:
        with pytest.raises(RequestTimeoutError) as excinfo:
            await transport.request("GET", "/servers/getVersion")
        ok(excinfo.value.context.retryable)
    finally:
        await transport.aclose()


async def test_connection_failure_maps_to_connection_error() -> None:
    config = ServerConfig(
        name="closed",
        url=AnyHttpUrl("http://127.0.0.1:9"),
        credential=CredentialReference(provider="memory", key="closed"),
        allow_insecure_http=True,
        connect_timeout=0.5,
        retry=RetryConfig(max_attempts=1, initial_delay=0.0, jitter=False),
    )
    transport = AsyncTransport(config, API_KEY)
    try:
        with pytest.raises(ConnectionFailedError):
            await transport.request("GET", "/servers/getVersion")
    finally:
        await transport.aclose()


async def test_tls_handshake_failure_maps_to_tls_error(fake_misp: FakeMisp) -> None:
    config = config_for(fake_misp, url=AnyHttpUrl(f"https://127.0.0.1:{fake_misp.port}"))
    transport = AsyncTransport(config, API_KEY)
    try:
        with pytest.raises(TLSVerificationError):
            await transport.request("GET", "/servers/getVersion")
    finally:
        await transport.aclose()


async def test_oversized_response_is_rejected(fake_misp: FakeMisp) -> None:
    transport = AsyncTransport(config_for(fake_misp), API_KEY, max_response_bytes=5)
    try:
        with pytest.raises(ResponseTooLargeError):
            await transport.request("GET", "/servers/getVersion")
    finally:
        await transport.aclose()


async def test_invalid_json_response_redacts_secrets_in_excerpt(fake_misp: FakeMisp) -> None:
    fake_misp.script(200, f"<html>error {API_KEY}</html>")
    transport = transport_for(fake_misp)
    try:
        with pytest.raises(InvalidResponseError) as excinfo:
            await transport.request("GET", "/servers/getVersion")
        excerpt = excinfo.value.context.safe_response_excerpt or ""
        not_contains(excerpt, API_KEY)
        contains(excerpt, "REDACTED")
    finally:
        await transport.aclose()


async def test_rate_limited_transport_spaces_requests(fake_misp: FakeMisp) -> None:
    transport = transport_for(fake_misp, rate_limit=100.0)
    try:
        await transport.request("GET", "/servers/getVersion")
        await transport.request("GET", "/servers/getVersion")
        eq(len(fake_misp.requests_seen), 2)
    finally:
        await transport.aclose()


async def test_tls_material_configuration_is_accepted(fake_misp: FakeMisp) -> None:
    with_key = transport_for(
        fake_misp,
        ca_bundle=Path(certifi.where()),
        client_certificate=FIXTURES / "client-cert.pem",
        client_key=FIXTURES / "client-key.pem",
    )
    await with_key.aclose()
    combined = transport_for(
        fake_misp,
        client_certificate=FIXTURES / "client-combined.pem",
    )
    await combined.aclose()
    ca_only = transport_for(fake_misp, ca_bundle=Path(certifi.where()))
    await ca_only.aclose()
    unverified_mtls = transport_for(
        fake_misp,
        verify_tls=False,
        client_certificate=FIXTURES / "client-combined.pem",
    )
    await unverified_mtls.aclose()


async def test_disabling_tls_verification_logs_a_warning(fake_misp: FakeMisp) -> None:
    import io
    import logging

    from mispfleet.logging import LOGGER_NAME, configure_cli_logging

    stream = io.StringIO()
    configure_cli_logging(level="warning", stream=stream)
    transport = transport_for(fake_misp, verify_tls=False)
    await transport.aclose()
    contains(stream.getvalue(), "TLS verification is DISABLED")
    logging.getLogger(LOGGER_NAME).handlers.clear()


async def test_abrupt_disconnect_maps_to_connection_error(fake_misp: FakeMisp) -> None:
    fake_misp.close_next = True
    transport = transport_for(fake_misp)
    try:
        with pytest.raises(ConnectionFailedError) as excinfo:
            await transport.request("GET", "/servers/getVersion")
        contains(str(excinfo.value), "transport failure")
    finally:
        await transport.aclose()
