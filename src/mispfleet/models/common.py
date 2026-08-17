"""Shared primitive types used across the domain."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from enum import StrEnum
from functools import wraps
from typing import Any, NewType

from pydantic import BaseModel, Field

from mispfleet.exceptions import InvalidResponseError

ServerName = NewType("ServerName", str)
EventIdentifier = NewType("EventIdentifier", str)


class ServerRole(StrEnum):
    """Operational role of a configured MISP server."""

    GENERAL = "general"
    PRIMARY = "primary"
    RESEARCH = "research"
    PARTNER = "partner"


class FailurePolicy(StrEnum):
    """How a fleet operation reacts to per-server failures."""

    CONTINUE = "continue"
    FAIL_FAST = "fail-fast"
    REQUIRE_ALL = "require-all"
    REQUIRE_ANY = "require-any"


class ExecutionOptions(BaseModel):
    """Tuning knobs for a fleet-wide operation."""

    max_concurrency: int = Field(default=10, ge=1)
    failure_policy: FailurePolicy = FailurePolicy.CONTINUE


class ServerError(BaseModel):
    """Typed, secret-free description of a per-server failure."""

    server: str
    kind: str
    message: str
    status_code: int | None = None
    retryable: bool = False


class OperationWarning(BaseModel):
    """Non-fatal condition observed during an operation."""

    server: str | None = None
    message: str


def optional_str(raw: Mapping[str, Any], key: str) -> str | None:
    """Read an optional string field, mapping a JSON ``null`` onto ``None``.

    A bare ``str(raw[key])`` turns a null into the literal text "None", which
    then travels to the destination server as if it were a real value.
    """
    value = raw.get(key)
    return str(value) if value is not None else None


def parses_misp[**P, R](entity: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Turn a malformed remote payload into a typed transport error.

    Remote data is a trust boundary: a MISP server answering with a missing
    field or an unexpected shape must surface as ``InvalidResponseError``,
    never as a raw ``KeyError`` escaping through the public API.
    """

    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        @wraps(function)
        def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
            try:
                return function(*args, **kwargs)
            except (KeyError, TypeError, AttributeError, ValueError) as error:
                detail = f"missing field {error}" if isinstance(error, KeyError) else str(error)
                raise InvalidResponseError(f"malformed {entity} payload: {detail}") from error

        return guarded

    return decorate
