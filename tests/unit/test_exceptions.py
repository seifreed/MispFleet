"""Unit tests for the exception hierarchy."""

from __future__ import annotations

from mispfleet.exceptions import (
    APIError,
    AuthenticationError,
    ConfigurationError,
    ErrorContext,
    MispFleetError,
    PartialFleetError,
    StalePlanError,
    TransportError,
)
from tests.support import eq, ok


def test_base_error_defaults_to_empty_context() -> None:
    error = MispFleetError("boom")
    eq(error.message, "boom")
    eq(error.context, ErrorContext())
    eq(str(error), "boom")


def test_error_preserves_explicit_context() -> None:
    context = ErrorContext(server="production", status_code=401, retryable=False)
    error = AuthenticationError("bad key", context)
    eq(error.context.server, "production")
    eq(error.context.status_code, 401)


def test_hierarchy_is_catchable_at_each_level() -> None:
    ok(issubclass(AuthenticationError, APIError))
    ok(issubclass(APIError, MispFleetError))
    ok(issubclass(ConfigurationError, MispFleetError))
    ok(issubclass(TransportError, MispFleetError))
    ok(issubclass(StalePlanError, MispFleetError))


def test_partial_fleet_error_carries_failed_servers() -> None:
    error = PartialFleetError("2 of 3 failed", failed_servers=["a", "b"])
    eq(error.failed_servers, ["a", "b"])
    eq(error.message, "2 of 3 failed")
