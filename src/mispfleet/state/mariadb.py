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
from urllib.parse import urlsplit
from uuid import UUID

from mispfleet.exceptions import StateError
from mispfleet.state.base import Checkpoint, OperationRecord

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS checkpoints ("
    " checkpoint_id VARCHAR(36) PRIMARY KEY,"
    " updated_at VARCHAR(40) NOT NULL,"
    " payload MEDIUMTEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS operations ("
    " operation_id VARCHAR(36) PRIMARY KEY,"
    " timestamp VARCHAR(40) NOT NULL,"
    " payload MEDIUMTEXT NOT NULL)",
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
        self._user = parts.username or "root"
        self._password = password if password is not None else (parts.password or "")
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
            return await asyncio.to_thread(guarded)

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
        updated = checkpoint.updated_at.isoformat()
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
        rows = await self._fetch_column("SELECT payload FROM checkpoints ORDER BY updated_at DESC")
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
                operation.timestamp.isoformat(),
                operation.model_dump_json(),
            ),
        )

    async def list_operations(self) -> list[OperationRecord]:
        """All stored operation records, newest first."""
        rows = await self._fetch_column("SELECT payload FROM operations ORDER BY timestamp DESC")
        return [OperationRecord.model_validate_json(row) for row in rows]

    async def prune(self, older_than: datetime) -> int:
        """Delete records older than the given instant; returns removals."""
        threshold = older_than.isoformat()
        removed = await self._execute("DELETE FROM checkpoints WHERE updated_at < %s", (threshold,))
        removed += await self._execute("DELETE FROM operations WHERE timestamp < %s", (threshold,))
        return removed

    async def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            connection = self._connection
            await asyncio.to_thread(connection.close)
            self._connection = None
