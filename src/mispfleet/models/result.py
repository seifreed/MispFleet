"""Result envelopes for multiserver operations."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from mispfleet.models.common import OperationWarning, ServerError


class MultiServerResult[T](BaseModel):
    """Envelope describing the outcome of an operation across several servers.

    A partial result is never represented as a total success: callers can
    inspect ``failed_servers`` and ``errors`` explicitly.
    """

    operation_id: UUID
    started_at: datetime
    completed_at: datetime
    duration_ms: float
    requested_servers: list[str]
    successful_servers: list[str]
    failed_servers: list[str]
    results: dict[str, T]
    errors: dict[str, ServerError] = Field(default_factory=dict)
    warnings: list[OperationWarning] = Field(default_factory=list)

    @property
    def complete(self) -> bool:
        """True when every requested server succeeded."""
        return not self.failed_servers

    @property
    def partial(self) -> bool:
        """True when at least one requested server failed."""
        return bool(self.failed_servers)


class MatchLevel(StrEnum):
    """Deterministic grouping levels for federated matches."""

    SAME_UUID = "same-uuid"
    SAME_CANONICAL_CONTENT = "same-canonical-content"
    SAME_VALUE_AND_TYPE = "same-value-and-type"
    SHARED_INDICATORS = "shared-indicators"
    POSSIBLE_MATCH = "possible-match"


class FederatedMatch(BaseModel):
    """A single normalized match returned by a federated search."""

    server: str
    event_id: str | None = None
    event_uuid: UUID | None = None
    attribute_id: str | None = None
    attribute_uuid: UUID | None = None
    value: str | None = None
    attribute_type: str | None = None
    category: str | None = None
    event_info: str | None = None
    tags: set[str] = Field(default_factory=set)
    fetched_at: datetime | None = None
    operation_id: UUID | None = None
    raw: dict[str, Any] | None = None


class MatchGroup(BaseModel):
    """A group of matches considered duplicates at a given match level."""

    level: MatchLevel
    key: str
    matches: list[FederatedMatch]


class FederatedSearchResult(MultiServerResult[list[FederatedMatch]]):
    """Aggregated federated search outcome with provenance-preserving matches."""

    matches: list[FederatedMatch] = Field(default_factory=list)
    groups: list[MatchGroup] = Field(default_factory=list)
    total_matches: int = 0
    unique_values: int = 0


class ServerHealth(BaseModel):
    """Health and capability snapshot of a single server."""

    server: str
    reachable: bool
    authenticated: bool
    read_only: bool = False
    latency_ms: float | None = None
    misp_version: str | None = None
    api_version: str | None = None
    tls_valid: bool | None = None
    certificate_expiry: datetime | None = None
    capabilities: set[str] = Field(default_factory=set)
    warnings: list[str] = Field(default_factory=list)
    error: ServerError | None = None


class FleetHealthResult(MultiServerResult[ServerHealth]):
    """Fleet-wide health outcome."""
