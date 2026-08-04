"""SQLite state backend built on aiosqlite.

The database stores no API keys, ever; records are serialized as JSON
documents indexed by identifier and timestamp.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import UUID

import aiosqlite

from mispfleet.exceptions import StateError
from mispfleet.state.base import CapabilityRecord, Checkpoint, OperationRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operations (
    operation_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capabilities (
    server TEXT PRIMARY KEY,
    fetched_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
"""


class SqliteStateBackend:
    """Durable local state under the platform state directory."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._connection: aiosqlite.Connection | None = None

    @property
    def path(self) -> Path:
        """Location of the database file."""
        return self._path

    @property
    def location(self) -> str:
        """Credential-free description of where state lives."""
        return str(self._path)

    async def initialize(self) -> None:
        """Create the schema and restrict file permissions."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = await aiosqlite.connect(self._path)
        await self._connection.executescript(_SCHEMA)
        await self._connection.commit()
        self._path.chmod(0o600)

    def _conn(self) -> aiosqlite.Connection:
        if self._connection is None:
            raise StateError("state backend is not initialized")
        return self._connection

    async def save_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Insert or update a checkpoint."""
        await self._conn().execute(
            "INSERT INTO checkpoints (checkpoint_id, updated_at, payload) VALUES (?, ?, ?) "
            "ON CONFLICT(checkpoint_id) DO UPDATE SET updated_at = ?, payload = ?",
            (
                str(checkpoint.checkpoint_id),
                checkpoint.updated_at.isoformat(),
                checkpoint.model_dump_json(),
                checkpoint.updated_at.isoformat(),
                checkpoint.model_dump_json(),
            ),
        )
        await self._conn().commit()

    async def load_checkpoint(self, checkpoint_id: UUID) -> Checkpoint:
        """Return a checkpoint or raise ``StateError``."""
        cursor = await self._conn().execute(
            "SELECT payload FROM checkpoints WHERE checkpoint_id = ?",
            (str(checkpoint_id),),
        )
        row = await cursor.fetchone()
        if row is None:
            raise StateError(f"unknown checkpoint {checkpoint_id}")
        return Checkpoint.model_validate_json(str(row[0]))

    async def list_checkpoints(self) -> list[Checkpoint]:
        """All stored checkpoints, newest first."""
        cursor = await self._conn().execute(
            "SELECT payload FROM checkpoints ORDER BY updated_at DESC"
        )
        rows = await cursor.fetchall()
        return [Checkpoint.model_validate_json(str(row[0])) for row in rows]

    async def delete_checkpoint(self, checkpoint_id: UUID) -> None:
        """Remove a checkpoint if present."""
        await self._conn().execute(
            "DELETE FROM checkpoints WHERE checkpoint_id = ?",
            (str(checkpoint_id),),
        )
        await self._conn().commit()

    async def save_operation(self, operation: OperationRecord) -> None:
        """Append an operation audit record."""
        await self._conn().execute(
            "INSERT INTO operations (operation_id, timestamp, payload) VALUES (?, ?, ?)",
            (
                str(operation.operation_id),
                operation.timestamp.isoformat(),
                operation.model_dump_json(),
            ),
        )
        await self._conn().commit()

    async def list_operations(self) -> list[OperationRecord]:
        """All stored operation records, newest first."""
        cursor = await self._conn().execute(
            "SELECT payload FROM operations ORDER BY timestamp DESC"
        )
        rows = await cursor.fetchall()
        return [OperationRecord.model_validate_json(str(row[0])) for row in rows]

    async def save_capabilities(self, record: CapabilityRecord) -> None:
        """Insert or update the cached capabilities for one server."""
        payload = record.model_dump_json()
        fetched = record.fetched_at.isoformat()
        await self._conn().execute(
            "INSERT INTO capabilities (server, fetched_at, payload) VALUES (?, ?, ?) "
            "ON CONFLICT(server) DO UPDATE SET fetched_at = ?, payload = ?",
            (record.server, fetched, payload, fetched, payload),
        )
        await self._conn().commit()

    async def load_capabilities(self, server: str) -> CapabilityRecord | None:
        """Return the cached capabilities for one server, if any."""
        cursor = await self._conn().execute(
            "SELECT payload FROM capabilities WHERE server = ?", (server,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return CapabilityRecord.model_validate_json(str(row[0]))

    async def invalidate_capabilities(self, server: str) -> None:
        """Drop the cached capabilities for one server."""
        await self._conn().execute("DELETE FROM capabilities WHERE server = ?", (server,))
        await self._conn().commit()

    async def prune(self, older_than: datetime) -> int:
        """Delete records older than the given instant; returns removals."""
        threshold = older_than.isoformat()
        checkpoints = await self._conn().execute(
            "DELETE FROM checkpoints WHERE updated_at < ?", (threshold,)
        )
        operations = await self._conn().execute(
            "DELETE FROM operations WHERE timestamp < ?", (threshold,)
        )
        await self._conn().commit()
        return checkpoints.rowcount + operations.rowcount

    async def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            await self._connection.close()
            self._connection = None
