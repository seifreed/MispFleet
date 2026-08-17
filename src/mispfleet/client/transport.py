"""Asynchronous HTTP transport with retry, throttling and secret redaction."""

from __future__ import annotations

import asyncio
import json
import math
import secrets
import ssl
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from uuid import uuid4

import httpx

from mispfleet.exceptions import (
    APIError,
    AuthenticationError,
    ConflictError,
    ConnectionFailedError,
    ErrorContext,
    InvalidResponseError,
    MispFleetError,
    MispServerError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    RequestTimeoutError,
    ResponseTooLargeError,
    TLSVerificationError,
    ValidationError,
)
from mispfleet.logging import get_logger
from mispfleet.models.server import ServerConfig
from mispfleet.observability import MetricsSink, current_operation_id
from mispfleet.redaction import redact_text

logger = get_logger("client.transport")

_RETRYABLE_STATUS = frozenset({429, 502, 503, 504})


def _parse_retry_after(raw: str | None) -> float | None:
    """Parse a ``Retry-After`` header: delay seconds or an HTTP-date (RFC 7231)."""
    if not raw:
        return None
    try:
        seconds = float(raw)
    except ValueError:
        try:
            instant = parsedate_to_datetime(raw)
        except TypeError, ValueError:
            return None
        # An HTTP-date is always GMT, but RFC 5322 '-0000' and offset-less
        # dates parse as naive and would make the subtraction raise TypeError.
        if instant.tzinfo is None:
            instant = instant.replace(tzinfo=UTC)
        seconds = (instant - datetime.now(tz=UTC)).total_seconds()
    if not math.isfinite(seconds):
        return None
    return max(0.0, seconds)


def _is_tls_failure(error: httpx.ConnectError) -> bool:
    cause: BaseException | None = error
    while cause is not None:
        if isinstance(cause, ssl.SSLError):
            return True
        cause = cause.__cause__ or cause.__context__
    return False


def build_verify(config: ServerConfig) -> ssl.SSLContext | bool:
    """Build the TLS configuration: custom CA bundle and mutual TLS support."""
    if config.ca_bundle is None and config.client_certificate is None:
        return config.verify_tls
    context = ssl.create_default_context(
        cafile=str(config.ca_bundle) if config.ca_bundle is not None else None
    )
    if not config.verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if config.client_certificate is not None:
        context.load_cert_chain(
            str(config.client_certificate),
            str(config.client_key) if config.client_key is not None else None,
        )
    return context


class AsyncTransport:
    """One authenticated httpx client per configured MISP server."""

    def __init__(
        self,
        config: ServerConfig,
        api_key: str,
        max_response_bytes: int | None = None,
        metrics: MetricsSink | None = None,
    ) -> None:
        self._config = config
        self._api_key = api_key
        self._max_response_bytes = max_response_bytes or config.max_response_bytes
        self._metrics = metrics or MetricsSink()
        self._semaphore = asyncio.Semaphore(config.concurrency)
        self._rate_lock = asyncio.Lock()
        self._min_interval = 1.0 / config.rate_limit if config.rate_limit else 0.0
        self._last_request_at = 0.0
        if not config.verify_tls:
            logger.warning("TLS verification is DISABLED for server %s", config.name)
        self._client = httpx.AsyncClient(
            base_url=str(config.url).rstrip("/"),
            headers={
                "Authorization": api_key,
                "Accept": "application/json",
                "User-Agent": "mispfleet",
            },
            verify=build_verify(config),
            proxy=config.proxy,
            timeout=httpx.Timeout(config.request_timeout, connect=config.connect_timeout),
            limits=httpx.Limits(
                max_connections=config.concurrency,
                max_keepalive_connections=config.max_keepalive_connections,
                keepalive_expiry=config.keepalive_expiry,
            ),
            http2=config.http2,
            follow_redirects=False,
        )

    @property
    def server_name(self) -> str:
        """Name of the server this transport talks to."""
        return self._config.name

    async def request(
        self,
        method: str,
        path: str,
        json_body: dict[str, Any] | list[Any] | None = None,
        idempotent: bool = True,
    ) -> Any:
        """Send one API request, retrying transient failures when safe.

        Non-idempotent requests are never retried: independent MISP servers
        give no idempotency guarantee for mutations.
        """
        attempts = self._config.retry.max_attempts if idempotent else 1
        attempt = 0
        while True:
            attempt += 1
            try:
                return await self._send_once(method, path, json_body)
            except MispFleetError as error:
                if not error.context.retryable or attempt >= attempts:
                    raise
                delay = self._backoff_delay(attempt, error)
                self._metrics.on_retry(self._config.name, path)
                logger.debug(
                    "retrying %s %s on %s (attempt %d, delay %.2fs)",
                    method,
                    path,
                    self._config.name,
                    attempt,
                    delay,
                )
                await asyncio.sleep(delay)

    def _backoff_delay(self, attempt: int, error: MispFleetError) -> float:
        retry = self._config.retry
        delay = min(retry.initial_delay * (retry.multiplier ** (attempt - 1)), retry.max_delay)
        if retry.jitter:
            delay *= secrets.SystemRandom().uniform(0.5, 1.0)
        # The server-mandated wait is a floor, so it is applied after jitter:
        # jittering it afterwards would retry inside the throttle window. It is
        # also capped: an unbounded Retry-After would let one hostile header
        # park the client in asyncio.sleep for years.
        if (
            retry.respect_retry_after
            and isinstance(error, RateLimitError)
            and error.retry_after is not None
        ):
            delay = max(delay, min(error.retry_after, retry.max_retry_after))
        return delay

    async def _throttle(self) -> None:
        if not self._min_interval:
            return
        async with self._rate_lock:
            loop = asyncio.get_running_loop()
            wait = self._last_request_at + self._min_interval - loop.time()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request_at = loop.time()

    def _log_context(self, path: str, request_id: str) -> dict[str, str]:
        context = {
            "server": self._config.name,
            "endpoint": path,
            "request_id": request_id,
        }
        operation_id = current_operation_id.get()
        if operation_id is not None:
            context["operation_id"] = operation_id
        return context

    async def _send_once(
        self, method: str, path: str, json_body: dict[str, Any] | list[Any] | None
    ) -> Any:
        async with self._semaphore:
            await self._throttle()
            request_id = uuid4().hex
            loop = asyncio.get_running_loop()
            started = loop.time()
            try:
                request = self._client.build_request(
                    method,
                    path,
                    json=json_body,
                    headers={"X-MispFleet-Request-ID": request_id},
                )
                response = await self._client.send(request, stream=True)
                try:
                    body = await self._read_limited(response, path, request_id)
                finally:
                    await response.aclose()
            except httpx.TimeoutException as error:
                self._metrics.on_error(self._config.name, path, "timeout")
                raise RequestTimeoutError(
                    f"request to {self._config.name} timed out",
                    self._context(path, request_id, retryable=True),
                ) from error
            except httpx.ConnectError as error:
                if _is_tls_failure(error):
                    self._metrics.on_error(self._config.name, path, "tls")
                    raise TLSVerificationError(
                        f"TLS verification failed for {self._config.name}",
                        self._context(path, request_id, retryable=False),
                    ) from error
                self._metrics.on_error(self._config.name, path, "connection")
                raise ConnectionFailedError(
                    f"connection to {self._config.name} failed",
                    self._context(path, request_id, retryable=True),
                ) from error
            except httpx.HTTPError as error:
                self._metrics.on_error(self._config.name, path, "transport")
                raise ConnectionFailedError(
                    f"transport failure talking to {self._config.name}: {type(error).__name__}",
                    self._context(path, request_id, retryable=True),
                ) from error
            self._metrics.on_request(
                self._config.name, path, loop.time() - started, response.status_code
            )
            logger.debug(
                "%s %s -> %d",
                method,
                path,
                response.status_code,
                extra=self._log_context(path, request_id),
            )
        if response.is_success:
            try:
                return json.loads(body)
            except (json.JSONDecodeError, ValueError) as error:
                raise InvalidResponseError(
                    f"non-JSON response from {self._config.name}",
                    self._context(
                        path,
                        request_id,
                        status_code=response.status_code,
                        retryable=False,
                        excerpt=self._safe_excerpt(body),
                    ),
                ) from error
        raise self._status_error(response, body, path, request_id)

    async def _read_limited(self, response: httpx.Response, path: str, request_id: str) -> bytes:
        """Read the response body without ever holding more than the size limit.

        The declared ``Content-Length`` is rejected up front; chunked or lying
        responses are cut off as soon as the streamed size crosses the limit.
        """
        too_large = ResponseTooLargeError(
            f"response from {self._config.name} exceeds {self._max_response_bytes} bytes",
            self._context(path, request_id, retryable=False),
        )
        declared = response.headers.get("Content-Length")
        if declared is not None and declared.isdigit() and int(declared) > self._max_response_bytes:
            raise too_large
        chunks = bytearray()
        async for chunk in response.aiter_bytes():
            chunks.extend(chunk)
            if len(chunks) > self._max_response_bytes:
                raise too_large
        return bytes(chunks)

    def _safe_excerpt(self, body: bytes) -> str:
        return redact_text(body[:300].decode("utf-8", errors="replace"), [self._api_key])

    def _context(
        self,
        path: str,
        request_id: str,
        status_code: int | None = None,
        retryable: bool = False,
        excerpt: str | None = None,
    ) -> ErrorContext:
        return ErrorContext(
            server=self._config.name,
            endpoint=path,
            status_code=status_code,
            retryable=retryable,
            request_id=request_id,
            safe_response_excerpt=excerpt,
        )

    def _status_error(
        self, response: httpx.Response, body: bytes, path: str, request_id: str
    ) -> MispFleetError:
        status = response.status_code
        retryable = status in _RETRYABLE_STATUS
        context = self._context(
            path,
            request_id,
            status_code=status,
            retryable=retryable,
            excerpt=self._safe_excerpt(body),
        )
        message = f"{self._config.name} returned HTTP {status} for {path}"
        if 300 <= status < 400:
            return InvalidResponseError(f"unexpected redirect ({status}) from {path}", context)
        if status in (400, 422):
            return ValidationError(message, context)
        if status == 401:
            return AuthenticationError(message, context)
        if status == 403:
            return PermissionDeniedError(message, context)
        if status == 404:
            return NotFoundError(message, context)
        if status == 409:
            return ConflictError(message, context)
        if status == 429:
            return RateLimitError(
                message,
                context,
                retry_after=_parse_retry_after(response.headers.get("Retry-After")),
            )
        if status >= 500:
            return MispServerError(message, context)
        return APIError(message, context)

    async def aclose(self) -> None:
        """Release the underlying connection pool."""
        await self._client.aclose()
