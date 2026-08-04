"""State backend contract and persisted record models."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, Field


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

    async def prune(self, older_than: datetime) -> int:
        """Delete records older than the given instant; returns removals."""
        ...

    async def close(self) -> None:
        """Release backend resources."""
        ...
