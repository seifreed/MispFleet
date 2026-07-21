"""In-memory state backend for tests and ephemeral runs."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from mispfleet.exceptions import StateError
from mispfleet.state.base import Checkpoint, OperationRecord


class MemoryStateBackend:
    """Keeps checkpoints and operation records in process memory."""

    def __init__(self) -> None:
        self._checkpoints: dict[UUID, Checkpoint] = {}
        self._operations: list[OperationRecord] = []

    async def initialize(self) -> None:
        """Nothing to prepare for the in-memory backend."""

    async def save_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Insert or update a checkpoint."""
        self._checkpoints[checkpoint.checkpoint_id] = checkpoint

    async def load_checkpoint(self, checkpoint_id: UUID) -> Checkpoint:
        """Return a checkpoint or raise ``StateError``."""
        try:
            return self._checkpoints[checkpoint_id]
        except KeyError:
            raise StateError(f"unknown checkpoint {checkpoint_id}") from None

    async def list_checkpoints(self) -> list[Checkpoint]:
        """All stored checkpoints, newest first."""
        return sorted(self._checkpoints.values(), key=lambda c: c.updated_at, reverse=True)

    async def delete_checkpoint(self, checkpoint_id: UUID) -> None:
        """Remove a checkpoint if present."""
        self._checkpoints.pop(checkpoint_id, None)

    async def save_operation(self, operation: OperationRecord) -> None:
        """Append an operation audit record."""
        self._operations.append(operation)

    async def list_operations(self) -> list[OperationRecord]:
        """All stored operation records, newest first."""
        return sorted(self._operations, key=lambda o: o.timestamp, reverse=True)

    async def prune(self, older_than: datetime) -> int:
        """Delete records older than the given instant; returns removals."""
        stale_checkpoints = [
            checkpoint_id
            for checkpoint_id, checkpoint in self._checkpoints.items()
            if checkpoint.updated_at < older_than
        ]
        for checkpoint_id in stale_checkpoints:
            del self._checkpoints[checkpoint_id]
        kept = [op for op in self._operations if op.timestamp >= older_than]
        removed = len(stale_checkpoints) + len(self._operations) - len(kept)
        self._operations = kept
        return removed

    async def close(self) -> None:
        """Nothing to release for the in-memory backend."""
