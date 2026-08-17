"""In-memory state backend for tests and ephemeral runs."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from mispfleet.exceptions import StateError
from mispfleet.state.base import (
    CapabilityRecord,
    Checkpoint,
    OperationRecord,
    PlanRecord,
    PluginRecord,
    QueryRecord,
    as_utc,
)


def _snapshot[RecordT: BaseModel](
    records: Iterable[RecordT],
    key: Callable[[RecordT], Any],
    reverse: bool = False,
) -> list[RecordT]:
    """Deep-copied records in a total order.

    The sort key ends in an identifier so records sharing a timestamp keep a
    stable order instead of falling back to insertion order, which the durable
    backends cannot reproduce.
    """
    return [record.model_copy(deep=True) for record in sorted(records, key=key, reverse=reverse)]


class MemoryStateBackend:
    """Keeps checkpoints and operation records in process memory.

        Records are copied on both save and load: the durable backends persist
    and re-parse a snapshot, so neither mutating a saved object nor mutating a
    loaded one may rewrite stored state here either.
    """

    def __init__(self) -> None:
        self._checkpoints: dict[UUID, Checkpoint] = {}
        self._operations: list[OperationRecord] = []
        self._capabilities: dict[str, CapabilityRecord] = {}
        self._plans: dict[UUID, PlanRecord] = {}
        self._queries: list[QueryRecord] = []
        self._plugins: dict[str, PluginRecord] = {}

    @property
    def location(self) -> str:
        """Credential-free description of where state lives."""
        return "memory"

    async def initialize(self) -> None:
        """Nothing to prepare for the in-memory backend."""

    async def save_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Insert or update a checkpoint."""
        self._checkpoints[checkpoint.checkpoint_id] = checkpoint.model_copy(deep=True)

    async def load_checkpoint(self, checkpoint_id: UUID) -> Checkpoint:
        """Return a checkpoint or raise ``StateError``."""
        try:
            return self._checkpoints[checkpoint_id].model_copy(deep=True)
        except KeyError:
            raise StateError(f"unknown checkpoint {checkpoint_id}") from None

    async def list_checkpoints(self) -> list[Checkpoint]:
        """All stored checkpoints, newest first."""
        return _snapshot(
            self._checkpoints.values(),
            key=lambda c: (as_utc(c.updated_at), str(c.checkpoint_id)),
            reverse=True,
        )

    async def delete_checkpoint(self, checkpoint_id: UUID) -> None:
        """Remove a checkpoint if present."""
        self._checkpoints.pop(checkpoint_id, None)

    async def save_operation(self, operation: OperationRecord) -> None:
        """Append an operation audit record."""
        # operation_id is the primary key on both durable backends, so storing
        # the same record twice must fail here too rather than let a test pass
        # against a shape production rejects.
        if any(record.operation_id == operation.operation_id for record in self._operations):
            raise StateError(f"operation {operation.operation_id} is already recorded")
        self._operations.append(operation.model_copy(deep=True))

    async def list_operations(self) -> list[OperationRecord]:
        """All stored operation records, newest first."""
        return _snapshot(
            self._operations,
            key=lambda o: (as_utc(o.timestamp), str(o.operation_id)),
            reverse=True,
        )

    async def save_capabilities(self, record: CapabilityRecord) -> None:
        """Insert or update the cached capabilities for one server."""
        self._capabilities[record.server] = record.model_copy(deep=True)

    async def load_capabilities(self, server: str) -> CapabilityRecord | None:
        """Return the cached capabilities for one server, if any."""
        record = self._capabilities.get(server)
        return None if record is None else record.model_copy(deep=True)

    async def invalidate_capabilities(self, server: str) -> None:
        """Drop the cached capabilities for one server."""
        self._capabilities.pop(server, None)

    async def save_plan(self, record: PlanRecord) -> None:
        """Insert or update the metadata of one generated plan."""
        self._plans[record.plan_id] = record.model_copy(deep=True)

    async def list_plans(self) -> list[PlanRecord]:
        """All stored plan records, newest first."""
        return _snapshot(
            self._plans.values(),
            key=lambda p: (as_utc(p.generated_at), str(p.plan_id)),
            reverse=True,
        )

    async def save_query(self, record: QueryRecord) -> None:
        """Append the fingerprint of one executed query."""
        self._queries.append(record.model_copy(deep=True))

    async def list_queries(self) -> list[QueryRecord]:
        """All stored query records, newest first."""
        return _snapshot(
            self._queries,
            key=lambda q: (as_utc(q.executed_at), q.fingerprint),
            reverse=True,
        )

    async def save_plugin(self, record: PluginRecord) -> None:
        """Insert or update the metadata of one discovered plugin."""
        self._plugins[record.name] = record.model_copy(deep=True)

    async def list_plugins(self) -> list[PluginRecord]:
        """All stored plugin records, by name."""
        return _snapshot(self._plugins.values(), key=lambda p: p.name)

    async def prune(self, older_than: datetime) -> int:
        """Delete records older than the given instant; returns removals."""
        threshold = as_utc(older_than)
        stale_checkpoints = [
            checkpoint_id
            for checkpoint_id, checkpoint in self._checkpoints.items()
            if as_utc(checkpoint.updated_at) < threshold
        ]
        for checkpoint_id in stale_checkpoints:
            del self._checkpoints[checkpoint_id]
        stale_plans = [
            plan_id
            for plan_id, plan in self._plans.items()
            if as_utc(plan.generated_at) < threshold
        ]
        for plan_id in stale_plans:
            del self._plans[plan_id]
        kept = [op for op in self._operations if as_utc(op.timestamp) >= threshold]
        kept_queries = [query for query in self._queries if as_utc(query.executed_at) >= threshold]
        removed = (
            len(stale_checkpoints)
            + len(stale_plans)
            + len(self._operations)
            - len(kept)
            + len(self._queries)
            - len(kept_queries)
        )
        self._operations = kept
        self._queries = kept_queries
        return removed

    async def close(self) -> None:
        """Nothing to release for the in-memory backend."""
