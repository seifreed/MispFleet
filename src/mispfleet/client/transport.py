"""Asynchronous HTTP transport with retry, throttling and secret redaction."""

from __future__ import annotations

import asyncio
import json
import secrets
import ssl
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
from mispfleet.redaction import redact_text

DEFAULT_MAX_RESPONSE_BYTES = 50 * 1024 * 1024

logger = get_logger("client.transport")

_RETRYABLE_STATUS = frozenset({429, 502, 503, 504})


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
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self._config = config
        self._api_key = api_key
        self._max_response_bytes = max_response_bytes
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
            limits=httpx.Limits(max_connections=config.concurrency),
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
        json_body: dict[str, Any] | None = None,
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
        if (
            retry.respect_retry_after
            and isinstance(error, RateLimitError)
            and error.retry_after is not None
        ):
            delay = max(delay, error.retry_after)
        if retry.jitter:
            delay *= secrets.SystemRandom().uniform(0.5, 1.0)
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

    async def _send_once(self, method: str, path: str, json_body: dict[str, Any] | None) -> Any:
        async with self._semaphore:
            await self._throttle()
            request_id = uuid4().hex
            try:
                response = await self._client.request(
                    method,
                    path,
                    json=json_body,
                    headers={"X-MispFleet-Request-ID": request_id},
                )
            except httpx.TimeoutException as error:
                raise RequestTimeoutError(
                    f"request to {self._config.name} timed out",
                    self._context(path, request_id, retryable=True),
                ) from error
            except httpx.ConnectError as error:
                if _is_tls_failure(error):
                    raise TLSVerificationError(
                        f"TLS verification failed for {self._config.name}",
                        self._context(path, request_id, retryable=False),
                    ) from error
                raise ConnectionFailedError(
                    f"connection to {self._config.name} failed",
                    self._context(path, request_id, retryable=True),
                ) from error
            except httpx.HTTPError as error:
                raise ConnectionFailedError(
                    f"transport failure talking to {self._config.name}: {type(error).__name__}",
                    self._context(path, request_id, retryable=True),
                ) from error
        if len(response.content) > self._max_response_bytes:
            raise ResponseTooLargeError(
                f"response from {self._config.name} exceeds " f"{self._max_response_bytes} bytes",
                self._context(path, request_id, retryable=False),
            )
        if response.is_success:
            try:
                return response.json()
            except (json.JSONDecodeError, ValueError) as error:
                raise InvalidResponseError(
                    f"non-JSON response from {self._config.name}",
                    self._context(
                        path,
                        request_id,
                        status_code=response.status_code,
                        retryable=False,
                        excerpt=self._safe_excerpt(response),
                    ),
                ) from error
        raise self._status_error(response, path, request_id)

    def _safe_excerpt(self, response: httpx.Response) -> str:
        return redact_text(response.text[:300], [self._api_key])

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

    def _status_error(self, response: httpx.Response, path: str, request_id: str) -> MispFleetError:
        status = response.status_code
        retryable = status in _RETRYABLE_STATUS
        context = self._context(
            path,
            request_id,
            status_code=status,
            retryable=retryable,
            excerpt=self._safe_excerpt(response),
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
            retry_after = response.headers.get("Retry-After")
            return RateLimitError(
                message,
                context,
                retry_after=float(retry_after) if retry_after else None,
            )
        if status >= 500:
            return MispServerError(message, context)
        return APIError(message, context)

    async def aclose(self) -> None:
        """Release the underlying connection pool."""
        await self._client.aclose()
