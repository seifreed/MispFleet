"""Shared primitive types used across the domain."""

from __future__ import annotations

from enum import StrEnum
from typing import NewType

from pydantic import BaseModel, Field

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
