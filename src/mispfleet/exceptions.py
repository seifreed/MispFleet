"""Typed exception hierarchy for MispFleet."""

from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel


class ErrorContext(BaseModel):
    """Safe, redacted diagnostic context attached to operational exceptions."""

    operation_id: UUID | None = None
    server: str | None = None
    endpoint: str | None = None
    status_code: int | None = None
    retryable: bool = False
    request_id: str | None = None
    safe_response_excerpt: str | None = None


class MispFleetError(Exception):
    """Base class for every error raised by MispFleet."""

    def __init__(self, message: str, context: ErrorContext | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context = context or ErrorContext()


class ConfigurationError(MispFleetError):
    """Invalid or unusable configuration."""


class InvalidConfigurationError(ConfigurationError):
    """The configuration file or model failed validation."""


class CredentialResolutionError(ConfigurationError):
    """A credential reference could not be resolved to a secret."""


class TransportError(MispFleetError):
    """Network-level failure talking to a MISP server."""


class ConnectionError(TransportError):
    """DNS, TCP or generic connection failure.

    Shadows the builtin of the same name inside this module only, because the
    exception hierarchy is part of the documented public API. ``mispfleet``
    code refers to it through an explicit import.
    """


ConnectionFailedError = ConnectionError
"""Backwards-compatible alias of :class:`ConnectionError`."""


class TLSVerificationError(TransportError):
    """TLS certificate verification failed."""


class RequestTimeoutError(TransportError):
    """The request exceeded its configured timeout."""


class ResponseTooLargeError(TransportError):
    """The response body exceeded the configured size limit."""


class InvalidResponseError(TransportError):
    """The server returned a response that could not be parsed."""


class APIError(MispFleetError):
    """The MISP API returned an error response."""


class AuthenticationError(APIError):
    """Authentication with the MISP server failed."""


class PermissionDeniedError(APIError):
    """The authenticated user lacks permission for the operation."""


class NotFoundError(APIError):
    """The requested resource does not exist on the server."""


class ConflictError(APIError):
    """The operation conflicts with existing server state."""


class RateLimitError(APIError):
    """The server rejected the request due to rate limiting."""

    def __init__(
        self,
        message: str,
        context: ErrorContext | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message, context)
        self.retry_after = retry_after


class ValidationError(APIError):
    """The server rejected the request payload as invalid."""


class MispServerError(APIError):
    """The MISP server failed internally."""


class CapabilityError(MispFleetError):
    """A server lacks a capability required by the operation."""


class PolicyError(MispFleetError):
    """Policy evaluation or configuration failure."""


class PolicyViolationError(PolicyError):
    """An event was rejected by a policy."""


class PolicyConfigurationError(PolicyError):
    """A policy definition is invalid."""


class PlanError(MispFleetError):
    """A plan could not be generated or applied."""


class StalePlanError(PlanError):
    """The plan no longer matches the current source state."""


class UnsafePlanError(PlanError):
    """The plan failed pre-application safety validation."""


class StateError(MispFleetError):
    """Local state backend failure."""


class AttachmentSecurityError(MispFleetError):
    """An attachment failed a filesystem-safety check."""


class PartialFleetError(MispFleetError):
    """A fleet operation failed on some servers under a strict failure policy."""

    def __init__(
        self,
        message: str,
        failed_servers: list[str],
        context: ErrorContext | None = None,
    ) -> None:
        super().__init__(message, context)
        self.failed_servers = failed_servers
