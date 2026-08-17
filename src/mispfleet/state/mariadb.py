"""MariaDB state backend (optional ``mariadb`` extra).

Runs PyMySQL's synchronous driver inside ``asyncio.to_thread``: state
operations are coarse-grained, so a dedicated asynchronous driver adds no
value. The database referenced by the DSN must already exist; the DSN is
always redacted before appearing in errors or logs.
"""

from __future__ import annotations

import asyncio
import importlib
from collections.abc import Callable
from datetime import datetime
from types import ModuleType
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import UUID

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

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS checkpoints ("
    " checkpoint_id VARCHAR(36) PRIMARY KEY,"
    " updated_at VARCHAR(40) NOT NULL,"
    " payload MEDIUMTEXT NOT NULL) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS operations ("
    " operation_id VARCHAR(36) PRIMARY KEY,"
    " timestamp VARCHAR(40) NOT NULL,"
    " payload MEDIUMTEXT NOT NULL) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS capabilities ("
    " server VARCHAR(255) PRIMARY KEY,"
    " fetched_at VARCHAR(40) NOT NULL,"
    " payload MEDIUMTEXT NOT NULL) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS plans ("
    " plan_id VARCHAR(36) PRIMARY KEY,"
    " generated_at VARCHAR(40) NOT NULL,"
    " payload MEDIUMTEXT NOT NULL) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS queries ("
    " id BIGINT AUTO_INCREMENT PRIMARY KEY,"
    " fingerprint VARCHAR(64) NOT NULL,"
    " executed_at VARCHAR(40) NOT NULL,"
    " payload MEDIUMTEXT NOT NULL) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
    "CREATE TABLE IF NOT EXISTS plugins ("
    " name VARCHAR(255) PRIMARY KEY,"
    " discovered_at VARCHAR(40) NOT NULL,"
    " payload MEDIUMTEXT NOT NULL) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
)


_PRUNE_STATEMENTS = (
    "DELETE FROM checkpoints WHERE updated_at < %s",
    "DELETE FROM operations WHERE timestamp < %s",
    "DELETE FROM plans WHERE generated_at < %s",
    "DELETE FROM queries WHERE executed_at < %s",
)


def load_mariadb_module(module_name: str = "pymysql") -> ModuleType:
    """Import the MySQL driver, translating a missing optional dependency."""
    try:
        return importlib.import_module(module_name)
    except ImportError as error:
        raise StateError(
            "the MariaDB state backend requires the 'mariadb' extra: "
            "pip install 'mispfleet[mariadb]'"
        ) from error


class MariaDBStateBackend:
    """Durable shared state in a MariaDB (or MySQL-compatible) database."""

    def __init__(
        self,
        dsn: str,
        password: str | None = None,
        module_name: str = "pymysql",
    ) -> None:
        parts = urlsplit(dsn)
        if parts.scheme not in ("mysql", "mariadb"):
            raise StateError(f"unsupported state DSN scheme {parts.scheme!r}; expected mysql://")
        self._host = parts.hostname or "127.0.0.1"
        self._port = parts.port or 3306
        # Percent-decoded: encoding is the only way to put an "@" or a ":" in
        # DSN userinfo, so such a password authenticated with the literal
        # "p%40ss" and always failed.
        self._user = unquote(parts.username) if parts.username else "root"
        self._password = (
            password
            if password is not None
            else (unquote(parts.password) if parts.password else "")
        )
        self._database = parts.path.strip("/") or "mispfleet"
        self._module_name = module_name
        self._error_classes: tuple[type[Exception], ...] = ()
        self._connection: Any = None
        self._lock = asyncio.Lock()

    @property
    def location(self) -> str:
        """Credential-free description of where state lives."""
        return f"mysql://{self._user}@{self._host}:{self._port}/{self._database}"

    async def initialize(self) -> None:
        """Connect and create the schema; the database itself must exist."""
        module = load_mariadb_module(self._module_name)
        self._error_classes = (module.MySQLError,)

        def connect() -> Any:
            try:
                return module.connect(
                    host=self._host,
                    port=self._port,
                    user=self._user,
                    password=self._password,
                    database=self._database,
                    charset="utf8mb4",
                    autocommit=True,
                )
            except module.MySQLError as error:
                raise StateError(f"cannot connect to {self.location}: {error}") from error

        self._connection = await asyncio.to_thread(connect)
        for statement in _SCHEMA:
            await self._execute(statement)

    def _conn(self) -> Any:
        if self._connection is None:
            raise StateError("state backend is not initialized")
        return self._connection

    async def _run[T](self, operation: Callable[[], T]) -> T:
        self._conn()

        def guarded() -> T:
            try:
                return operation()
            except self._error_classes as error:
                raise StateError(f"MariaDB error on {self.location}: {error}") from error

        async with self._lock:
            worker = asyncio.ensure_future(asyncio.to_thread(guarded))
            try:
                return await asyncio.shield(worker)
            except asyncio.CancelledError:
                # asyncio.to_thread cannot be interrupted, and a PyMySQL
                # connection is not thread-safe. Releasing the lock here would
                # let the next caller interleave packets on the same socket
                # with the statement still running, so wait it out first.
                await asyncio.wait({worker})
                raise

    async def _execute(self, sql: str, params: tuple[str, ...] = ()) -> int:
        def operation() -> int:
            with self._conn().cursor() as cursor:
                cursor.execute(sql, params or None)
                return int(cursor.rowcount)

        return await self._run(operation)

    async def _fetch_column(self, sql: str, params: tuple[str, ...] = ()) -> list[str]:
        def operation() -> list[str]:
            with self._conn().cursor() as cursor:
                cursor.execute(sql, params or None)
                return [str(row[0]) for row in cursor.fetchall()]

        return await self._run(operation)

    async def save_checkpoint(self, checkpoint: Checkpoint) -> None:
        """Insert or update a checkpoint."""
        updated = sortable(checkpoint.updated_at)
        payload = checkpoint.model_dump_json()
        await self._execute(
            "INSERT INTO checkpoints (checkpoint_id, updated_at, payload)"
            " VALUES (%s, %s, %s)"
            " ON DUPLICATE KEY UPDATE updated_at = %s, payload = %s",
            (str(checkpoint.checkpoint_id), updated, payload, updated, payload),
        )

    async def load_checkpoint(self, checkpoint_id: UUID) -> Checkpoint:
        """Return a checkpoint or raise ``StateError``."""
        rows = await self._fetch_column(
            "SELECT payload FROM checkpoints WHERE checkpoint_id = %s",
            (str(checkpoint_id),),
        )
        if not rows:
            raise StateError(f"unknown checkpoint {checkpoint_id}")
        return Checkpoint.model_validate_json(rows[0])

    async def list_checkpoints(self) -> list[Checkpoint]:
        """All stored checkpoints, newest first."""
        rows = await self._fetch_column(
            "SELECT payload FROM checkpoints ORDER BY updated_at DESC, checkpoint_id DESC"
        )
        return [Checkpoint.model_validate_json(row) for row in rows]

    async def delete_checkpoint(self, checkpoint_id: UUID) -> None:
        """Remove a checkpoint if present."""
        await self._execute(
            "DELETE FROM checkpoints WHERE checkpoint_id = %s",
            (str(checkpoint_id),),
        )

    async def save_operation(self, operation: OperationRecord) -> None:
        """Append an operation audit record."""
        await self._execute(
            "INSERT INTO operations (operation_id, timestamp, payload) VALUES (%s, %s, %s)",
            (
                str(operation.operation_id),
                sortable(operation.timestamp),
                operation.model_dump_json(),
            ),
        )

    async def list_operations(self) -> list[OperationRecord]:
        """All stored operation records, newest first."""
        rows = await self._fetch_column(
            "SELECT payload FROM operations ORDER BY timestamp DESC, operation_id DESC"
        )
        return [OperationRecord.model_validate_json(row) for row in rows]

    async def save_capabilities(self, record: CapabilityRecord) -> None:
        """Insert or update the cached capabilities for one server."""
        fetched = sortable(record.fetched_at)
        payload = record.model_dump_json()
        await self._execute(
            "INSERT INTO capabilities (server, fetched_at, payload) VALUES (%s, %s, %s)"
            " ON DUPLICATE KEY UPDATE fetched_at = %s, payload = %s",
            (record.server, fetched, payload, fetched, payload),
        )

    async def load_capabilities(self, server: str) -> CapabilityRecord | None:
        """Return the cached capabilities for one server, if any."""
        rows = await self._fetch_column(
            "SELECT payload FROM capabilities WHERE server = %s", (server,)
        )
        if not rows:
            return None
        return CapabilityRecord.model_validate_json(rows[0])

    async def invalidate_capabilities(self, server: str) -> None:
        """Drop the cached capabilities for one server."""
        await self._execute("DELETE FROM capabilities WHERE server = %s", (server,))

    async def save_plan(self, record: PlanRecord) -> None:
        """Insert or update the metadata of one generated plan."""
        generated = sortable(record.generated_at)
        payload = record.model_dump_json()
        await self._execute(
            "INSERT INTO plans (plan_id, generated_at, payload) VALUES (%s, %s, %s)"
            " ON DUPLICATE KEY UPDATE generated_at = %s, payload = %s",
            (str(record.plan_id), generated, payload, generated, payload),
        )

    async def list_plans(self) -> list[PlanRecord]:
        """All stored plan records, newest first."""
        rows = await self._fetch_column(
            "SELECT payload FROM plans ORDER BY generated_at DESC, plan_id DESC"
        )
        return [PlanRecord.model_validate_json(row) for row in rows]

    async def save_query(self, record: QueryRecord) -> None:
        """Append the fingerprint of one executed query."""
        await self._execute(
            "INSERT INTO queries (fingerprint, executed_at, payload) VALUES (%s, %s, %s)",
            (record.fingerprint, sortable(record.executed_at), record.model_dump_json()),
        )

    async def list_queries(self) -> list[QueryRecord]:
        """All stored query records, newest first."""
        rows = await self._fetch_column(
            "SELECT payload FROM queries ORDER BY executed_at DESC, fingerprint DESC"
        )
        return [QueryRecord.model_validate_json(row) for row in rows]

    async def save_plugin(self, record: PluginRecord) -> None:
        """Insert or update the metadata of one discovered plugin."""
        discovered = sortable(record.discovered_at)
        payload = record.model_dump_json()
        await self._execute(
            "INSERT INTO plugins (name, discovered_at, payload) VALUES (%s, %s, %s)"
            " ON DUPLICATE KEY UPDATE discovered_at = %s, payload = %s",
            (record.name, discovered, payload, discovered, payload),
        )

    async def list_plugins(self) -> list[PluginRecord]:
        """All stored plugin records, by name."""
        rows = await self._fetch_column("SELECT payload FROM plugins ORDER BY name")
        return [PluginRecord.model_validate_json(row) for row in rows]

    async def prune(self, older_than: datetime) -> int:
        """Delete records older than the given instant; returns removals."""
        threshold = sortable(older_than)

        def operation() -> int:
            connection = self._conn()
            # autocommit is on, so each DELETE would otherwise land on its own.
            # A failure midway through would leave checkpoints pruned and
            # operations kept, which the SQLite backend never does.
            connection.begin()
            try:
                removed = 0
                with connection.cursor() as cursor:
                    for sql in _PRUNE_STATEMENTS:
                        cursor.execute(sql, (threshold,))
                        removed += int(cursor.rowcount)
                connection.commit()
                return removed
            except BaseException:
                connection.rollback()
                raise

        return await self._run(operation)

    async def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            connection = self._connection
            await asyncio.to_thread(connection.close)
            self._connection = None
