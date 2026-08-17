"""SQLite state backend built on aiosqlite.

The database stores no API keys, ever; records are serialized as JSON
documents indexed by identifier and timestamp.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import aiosqlite

from mispfleet.exceptions import StateError
from mispfleet.state.base import (
    CapabilityRecord,
    Checkpoint,
    OperationRecord,
    PlanRecord,
    PluginRecord,
    QueryRecord,
    sortable,
)

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
CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT PRIMARY KEY,
    generated_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS queries (
    fingerprint TEXT NOT NULL,
    executed_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plugins (
    name TEXT PRIMARY KEY,
    discovered_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
"""


class SqliteStateBackend:
    """Durable local state under the platform state directory."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._connection: aiosqlite.Connection | None = None
        # One implicit transaction exists per connection, and the connection is
        # shared by every task. Without this, a task cancelled between its
        # statement and its commit leaves the statement inside whatever
        # transaction the next task happens to commit.
        self._lock = asyncio.Lock()

    @property
    def path(self) -> Path:
        """Location of the database file."""
        return self._path

    @property
    def location(self) -> str:
        """Credential-free description of where state lives."""
        return str(self._path)

    async def initialize(self) -> None:
        """Create the schema in a file that is owner-only from the start."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # The file must never exist with permissive modes, not even briefly:
        # create it empty and locked down before SQLite writes any record.
        os.close(os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600))
        self._path.chmod(0o600)
        connection = await aiosqlite.connect(self._path)
        try:
            await connection.executescript(_SCHEMA)
            await connection.commit()
        except BaseException:
            # aiosqlite's worker is a non-daemon thread: leaving it running
            # after a failed schema step hangs the interpreter at exit.
            await connection.close()
            raise
        self._connection = connection

    def _conn(self) -> aiosqlite.Connection:
        if self._connection is None:
            raise StateError("state backend is not initialized")
        return self._connection

    @asynccontextmanager
    async def _driver_errors(self) -> AsyncIterator[aiosqlite.Connection]:
        """Translate driver failures into the ``StateError`` the contract states.

        Callers catch ``StateError``; a bare ``sqlite3.IntegrityError`` from a
        duplicate insert, or ``OperationalError`` when a second process holds
        the file lock, would otherwise escape untyped — the MariaDB backend
        wraps the same failures through ``_run``.
        """
        connection = self._conn()
        try:
            yield connection
        except sqlite3.Error as error:
            raise StateError(f"SQLite error on {self._path}: {error}") from error

    async def _write(self, statements: Sequence[tuple[str, tuple[Any, ...]]]) -> int:
        """Run statements as one transaction and return the rows they touched."""
        async with self._lock, self._driver_errors() as connection:
            try:
                changed = 0
                for sql, parameters in statements:
                    cursor = await connection.execute(sql, parameters)
                    changed += cursor.rowcount
                await connection.commit()
                return changed
            except BaseException:
                # Statements that already ran sit in the connection's open
                # implicit transaction. Without this, the next writer's commit
                # makes them durable — a half-applied prune, or a record whose
                # caller was told the call failed.
                await connection.rollback()
                raise

    async def _read(self, sql: str, parameters: tuple[Any, ...] = ()) -> list[str]:
        """Return the first column of every row the query selects."""
        async with self._lock, self._driver_errors() as connection:
            cursor = await connection.execute(sql, parameters)
            return [str(row[0]) for row in await cursor.fetchall()]

    async def save_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Insert or update a checkpoint."""
        payload = checkpoint.model_dump_json()
        updated = sortable(checkpoint.updated_at)
        await self._write(
            [
                (
                    "INSERT INTO checkpoints (checkpoint_id, updated_at, payload) VALUES (?, ?, ?) "
                    "ON CONFLICT(checkpoint_id) DO UPDATE SET updated_at = ?, payload = ?",
                    (str(checkpoint.checkpoint_id), updated, payload, updated, payload),
                )
            ]
        )

    async def load_checkpoint(self, checkpoint_id: UUID) -> Checkpoint:
        """Return a checkpoint or raise ``StateError``."""
        rows = await self._read(
            "SELECT payload FROM checkpoints WHERE checkpoint_id = ?",
            (str(checkpoint_id),),
        )
        if not rows:
            raise StateError(f"unknown checkpoint {checkpoint_id}")
        return Checkpoint.model_validate_json(rows[0])

    async def list_checkpoints(self) -> list[Checkpoint]:
        """All stored checkpoints, newest first."""
        rows = await self._read(
            "SELECT payload FROM checkpoints ORDER BY updated_at DESC, checkpoint_id DESC"
        )
        return [Checkpoint.model_validate_json(row) for row in rows]

    async def delete_checkpoint(self, checkpoint_id: UUID) -> None:
        """Remove a checkpoint if present."""
        await self._write(
            [("DELETE FROM checkpoints WHERE checkpoint_id = ?", (str(checkpoint_id),))]
        )

    async def save_operation(self, operation: OperationRecord) -> None:
        """Append an operation audit record."""
        await self._write(
            [
                (
                    "INSERT INTO operations (operation_id, timestamp, payload) VALUES (?, ?, ?)",
                    (
                        str(operation.operation_id),
                        sortable(operation.timestamp),
                        operation.model_dump_json(),
                    ),
                )
            ]
        )

    async def list_operations(self) -> list[OperationRecord]:
        """All stored operation records, newest first."""
        rows = await self._read(
            "SELECT payload FROM operations ORDER BY timestamp DESC, operation_id DESC"
        )
        return [OperationRecord.model_validate_json(row) for row in rows]

    async def save_capabilities(self, record: CapabilityRecord) -> None:
        """Insert or update the cached capabilities for one server."""
        payload = record.model_dump_json()
        fetched = sortable(record.fetched_at)
        await self._write(
            [
                (
                    "INSERT INTO capabilities (server, fetched_at, payload) VALUES (?, ?, ?) "
                    "ON CONFLICT(server) DO UPDATE SET fetched_at = ?, payload = ?",
                    (record.server, fetched, payload, fetched, payload),
                )
            ]
        )

    async def load_capabilities(self, server: str) -> CapabilityRecord | None:
        """Return the cached capabilities for one server, if any."""
        rows = await self._read("SELECT payload FROM capabilities WHERE server = ?", (server,))
        if not rows:
            return None
        return CapabilityRecord.model_validate_json(rows[0])

    async def invalidate_capabilities(self, server: str) -> None:
        """Drop the cached capabilities for one server."""
        await self._write([("DELETE FROM capabilities WHERE server = ?", (server,))])

    async def save_plan(self, record: PlanRecord) -> None:
        """Insert or update the metadata of one generated plan."""
        payload = record.model_dump_json()
        generated = sortable(record.generated_at)
        await self._write(
            [
                (
                    "INSERT INTO plans (plan_id, generated_at, payload) VALUES (?, ?, ?) "
                    "ON CONFLICT(plan_id) DO UPDATE SET generated_at = ?, payload = ?",
                    (str(record.plan_id), generated, payload, generated, payload),
                )
            ]
        )

    async def list_plans(self) -> list[PlanRecord]:
        """All stored plan records, newest first."""
        rows = await self._read(
            "SELECT payload FROM plans ORDER BY generated_at DESC, plan_id DESC"
        )
        return [PlanRecord.model_validate_json(row) for row in rows]

    async def save_query(self, record: QueryRecord) -> None:
        """Append the fingerprint of one executed query."""
        await self._write(
            [
                (
                    "INSERT INTO queries (fingerprint, executed_at, payload) VALUES (?, ?, ?)",
                    (
                        record.fingerprint,
                        sortable(record.executed_at),
                        record.model_dump_json(),
                    ),
                )
            ]
        )

    async def list_queries(self) -> list[QueryRecord]:
        """All stored query records, newest first."""
        rows = await self._read(
            "SELECT payload FROM queries ORDER BY executed_at DESC, fingerprint DESC"
        )
        return [QueryRecord.model_validate_json(row) for row in rows]

    async def save_plugin(self, record: PluginRecord) -> None:
        """Insert or update the metadata of one discovered plugin."""
        payload = record.model_dump_json()
        discovered = sortable(record.discovered_at)
        await self._write(
            [
                (
                    "INSERT INTO plugins (name, discovered_at, payload) VALUES (?, ?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET discovered_at = ?, payload = ?",
                    (record.name, discovered, payload, discovered, payload),
                )
            ]
        )

    async def list_plugins(self) -> list[PluginRecord]:
        """All stored plugin records, by name."""
        rows = await self._read("SELECT payload FROM plugins ORDER BY name")
        return [PluginRecord.model_validate_json(row) for row in rows]

    async def prune(self, older_than: datetime) -> int:
        """Delete records older than the given instant; returns removals."""
        threshold = sortable(older_than)
        return await self._write(
            [
                ("DELETE FROM checkpoints WHERE updated_at < ?", (threshold,)),
                ("DELETE FROM operations WHERE timestamp < ?", (threshold,)),
                ("DELETE FROM plans WHERE generated_at < ?", (threshold,)),
                ("DELETE FROM queries WHERE executed_at < ?", (threshold,)),
            ]
        )

    async def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            await self._connection.close()
            self._connection = None
