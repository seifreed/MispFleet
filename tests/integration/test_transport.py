"""Integration tests for the HTTP transport against a real local server."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
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
    # A low rate (4 req/s → 250ms spacing) guarantees the second request is
    # throttled: the localhost round trip is far shorter than the interval.
    transport = transport_for(fake_misp, rate_limit=4.0)
    try:
        loop = asyncio.get_running_loop()
        start = loop.time()
        await transport.request("GET", "/servers/getVersion")
        await transport.request("GET", "/servers/getVersion")
        ok(loop.time() - start >= 0.25)
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


async def test_rate_limit_retry_after_accepts_http_dates(fake_misp: FakeMisp) -> None:
    from email.utils import format_datetime

    future = format_datetime(datetime.now(tz=UTC) + timedelta(seconds=30), usegmt=True)
    fake_misp.script(429, '{"message": "slow down"}', {"Retry-After": future})
    fake_misp.script(429, '{"message": "slow down"}', {"Retry-After": "not-a-date"})
    transport = transport_for(fake_misp)
    try:
        with pytest.raises(RateLimitError) as dated:
            await transport.request("GET", "/servers/getVersion")
        retry_after = dated.value.retry_after
        ok(retry_after is not None and 0.0 < retry_after <= 30.0)
        with pytest.raises(RateLimitError) as garbage:
            await transport.request("GET", "/servers/getVersion")
        eq(garbage.value.retry_after, None)
    finally:
        await transport.aclose()


async def test_rate_limit_retry_after_accepts_offset_less_http_dates(
    fake_misp: FakeMisp,
) -> None:
    """RFC 5322 '-0000' and bare dates parse as naive datetimes.

    Subtracting one from an aware 'now' raised TypeError, so the retryable
    RateLimitError never reached the caller and the retry never happened.
    """
    naive = (datetime.now(tz=UTC) + timedelta(seconds=30)).strftime("%a, %d %b %Y %H:%M:%S -0000")
    fake_misp.script(429, '{"message": "slow down"}', {"Retry-After": naive})
    transport = transport_for(fake_misp)
    try:
        with pytest.raises(RateLimitError) as excinfo:
            await transport.request("GET", "/servers/getVersion")
        retry_after = excinfo.value.retry_after
        ok(retry_after is not None and 0.0 < retry_after <= 30.0)
    finally:
        await transport.aclose()


async def test_backoff_never_undercuts_the_server_mandated_wait(fake_misp: FakeMisp) -> None:
    """Jitter applied after the Retry-After floor could halve it.

    The client then retried inside the throttle window and burned its whole
    attempt budget against a server that had already said "wait".
    """
    transport = transport_for(fake_misp, retry=RetryConfig(jitter=True, max_delay=1.0))
    error = RateLimitError("slow down", retry_after=60.0)
    try:
        delays = [transport._backoff_delay(attempt, error) for attempt in range(1, 6)]
        ok(all(delay >= 60.0 for delay in delays), f"backoff undercut Retry-After: {delays}")
    finally:
        await transport.aclose()


async def test_rate_limit_retry_after_rejects_non_finite_delays(fake_misp: FakeMisp) -> None:
    """'inf' parses as a float and would make the retry sleep forever."""
    fake_misp.script(429, '{"message": "slow down"}', {"Retry-After": "inf"})
    transport = transport_for(fake_misp)
    try:
        with pytest.raises(RateLimitError) as excinfo:
            await transport.request("GET", "/servers/getVersion")
        eq(excinfo.value.retry_after, None)
    finally:
        await transport.aclose()


async def test_read_limited_cuts_off_streams_without_content_length(
    fake_misp: FakeMisp,
) -> None:
    import httpx

    class _Chunks(httpx.AsyncByteStream):
        def __init__(self, chunks: list[bytes]) -> None:
            self._chunks = chunks

        async def __aiter__(self) -> Any:
            for chunk in self._chunks:
                yield chunk

    transport = AsyncTransport(config_for(fake_misp), API_KEY, max_response_bytes=5)
    try:
        oversized = httpx.Response(200, stream=_Chunks([b"aaa", b"bbb"]))
        with pytest.raises(ResponseTooLargeError):
            await transport._read_limited(oversized, "/x", "rid")
        lying = httpx.Response(200, headers={"Content-Length": "huge"}, stream=_Chunks([b"tiny"]))
        eq(await transport._read_limited(lying, "/x", "rid"), b"tiny")
    finally:
        await transport.aclose()


async def test_backoff_caps_a_hostile_retry_after(fake_misp: FakeMisp) -> None:
    """An unbounded Retry-After parked the client in sleep for years.

    'Retry-After: 99999999' produced a 3.2-year delay that retry.max_delay
    could not bound, because the floor was applied after the cap.
    """
    transport = transport_for(
        fake_misp, retry=RetryConfig(jitter=False, max_delay=1.0, max_retry_after=300.0)
    )
    error = RateLimitError("slow down", retry_after=99_999_999.0)
    try:
        eq(transport._backoff_delay(1, error), 300.0)
        polite = RateLimitError("slow down", retry_after=42.0)
        eq(transport._backoff_delay(1, polite), 42.0)
    finally:
        await transport.aclose()
