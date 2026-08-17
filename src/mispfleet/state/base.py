"""State backend contract and persisted record models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, Field


def as_utc(instant: datetime) -> datetime:
    """Normalize an instant to aware UTC, reading a naive value as UTC.

    Every backend must order and prune by the instant a record represents,
    never by the offset it happens to be printed in.
    """
    aware = instant if instant.tzinfo is not None else instant.replace(tzinfo=UTC)
    return aware.astimezone(UTC)


def sortable(instant: datetime) -> str:
    """UTC timestamp whose lexicographic order matches chronological order."""
    return as_utc(instant).isoformat()


class Checkpoint(BaseModel):
    """Resumable position inside a long paginated operation."""

    checkpoint_id: UUID
    operation_type: str
    query_fingerprint: str
    server: str
    page: int
    last_entity_uuid: str | None = None
    record_count: int = 0
    created_at: datetime
    updated_at: datetime
    client_version: str
    server_version: str | None = None


class CapabilityRecord(BaseModel):
    """Cached capability and version discovery result for one server."""

    server: str
    misp_version: str | None = None
    capabilities: set[str] = Field(default_factory=set)
    fetched_at: datetime
    expires_at: datetime | None = None

    def expired(self, now: datetime) -> bool:
        """Whether the cache entry is past its expiry instant."""
        return self.expires_at is not None and now >= self.expires_at


class OperationRecord(BaseModel):
    """Secret-free audit record of one mutating operation."""

    operation_id: UUID
    kind: str
    timestamp: datetime
    source_server: str | None = None
    destination_server: str | None = None
    event_identifier: str | None = None
    plan_fingerprint: str | None = None
    policy: str | None = None
    result: str
    error: str | None = None
    actor: str | None = None


class PlanRecord(BaseModel):
    """Secret-free metadata of one generated operation plan."""

    plan_id: UUID
    kind: str
    schema_version: str
    fingerprint: str
    source_server: str | None = None
    destination_server: str | None = None
    event_identifier: str | None = None
    policy: str | None = None
    on_conflict: str | None = None
    generated_at: datetime
    expires_at: datetime | None = None
    transformations: int = 0
    validations: int = 0
    warnings: int = 0
    blocking_errors: int = 0


class QueryRecord(BaseModel):
    """Fingerprint of one executed query, for auditing and checkpoint matching."""

    fingerprint: str
    operation: str
    servers: list[str] = Field(default_factory=list)
    executed_at: datetime
    record_count: int = 0


class PluginRecord(BaseModel):
    """Metadata of one discovered plugin entry point."""

    name: str
    target: str
    discovered_at: datetime
    version: str | None = None
    category: str | None = None
    compatible_with: str | None = None


@runtime_checkable
class StateBackend(Protocol):
    """Persistence contract for checkpoints and operation records."""

    @property
    def location(self) -> str:
        """Credential-free description of where state lives."""
        ...

    async def initialize(self) -> None:
        """Prepare the backend (create schema, directories, permissions)."""
        ...

    async def save_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Insert or update a checkpoint."""
        ...

    async def load_checkpoint(self, checkpoint_id: UUID) -> Checkpoint:
        """Return a checkpoint or raise ``StateError``."""
        ...

    async def list_checkpoints(self) -> list[Checkpoint]:
        """All stored checkpoints, newest first."""
        ...

    async def delete_checkpoint(self, checkpoint_id: UUID) -> None:
        """Remove a checkpoint if present."""
        ...

    async def save_operation(self, operation: OperationRecord) -> None:
        """Append an operation audit record."""
        ...

    async def save_capabilities(self, record: CapabilityRecord) -> None:
        """Insert or update the cached capabilities for one server."""
        ...

    async def load_capabilities(self, server: str) -> CapabilityRecord | None:
        """Return the cached capabilities for one server, if any."""
        ...

    async def invalidate_capabilities(self, server: str) -> None:
        """Drop the cached capabilities for one server."""
        ...

    async def list_operations(self) -> list[OperationRecord]:
        """All stored operation records, newest first."""
        ...

    async def save_plan(self, record: PlanRecord) -> None:
        """Insert or update the metadata of one generated plan."""
        ...

    async def list_plans(self) -> list[PlanRecord]:
        """All stored plan records, newest first."""
        ...

    async def save_query(self, record: QueryRecord) -> None:
        """Append the fingerprint of one executed query."""
        ...

    async def list_queries(self) -> list[QueryRecord]:
        """All stored query records, newest first."""
        ...

    async def save_plugin(self, record: PluginRecord) -> None:
        """Insert or update the metadata of one discovered plugin."""
        ...

    async def list_plugins(self) -> list[PluginRecord]:
        """All stored plugin records, by name."""
        ...

    async def prune(self, older_than: datetime) -> int:
        """Delete records older than the given instant; returns removals."""
        ...

    async def close(self) -> None:
        """Release backend resources."""
        ...
