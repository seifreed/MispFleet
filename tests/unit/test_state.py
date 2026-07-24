"""Unit tests for state backends; SQLite runs against real temporary files."""

from __future__ import annotations

import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mispfleet.exceptions import StateError
from mispfleet.state import (
    MariaDBStateBackend,
    MemoryStateBackend,
    SqliteStateBackend,
    StateBackend,
)
from tests.state_lifecycle import checkpoint, exercise_backend, operation
from tests.support import eq, ok


async def test_memory_backend_full_lifecycle() -> None:
    await exercise_backend(MemoryStateBackend())


async def test_sqlite_backend_full_lifecycle(tmp_path: Path) -> None:
    await exercise_backend(SqliteStateBackend(tmp_path / "nested" / "state.db"))


async def test_sqlite_backend_persists_across_connections(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    first = SqliteStateBackend(path)
    await first.initialize()
    record = operation()
    await first.save_operation(record)
    await first.close()
    second = SqliteStateBackend(path)
    await second.initialize()
    operations = await second.list_operations()
    eq([o.operation_id for o in operations], [record.operation_id])
    await second.close()


async def test_sqlite_backend_restricts_file_permissions(tmp_path: Path) -> None:
    backend = SqliteStateBackend(tmp_path / "state.db")
    await backend.initialize()
    mode = stat.S_IMODE(backend.path.stat().st_mode)
    eq(mode, 0o600)
    eq(backend.location, str(backend.path))
    await backend.close()


async def test_sqlite_backend_requires_initialization(tmp_path: Path) -> None:
    backend = SqliteStateBackend(tmp_path / "state.db")
    with pytest.raises(StateError):
        await backend.list_operations()
    await backend.close()


async def test_sqlite_prune_on_old_checkpoints(tmp_path: Path) -> None:
    backend = SqliteStateBackend(tmp_path / "state.db")
    await backend.initialize()
    await backend.save_checkpoint(checkpoint(age_minutes=120))
    removed = await backend.prune(datetime.now(tz=UTC))
    eq(removed, 1)
    eq(await backend.list_checkpoints(), [])
    await backend.close()


async def test_memory_prune_removes_old_checkpoints() -> None:
    backend = MemoryStateBackend()
    await backend.initialize()
    eq(backend.location, "memory")
    await backend.save_checkpoint(checkpoint(age_minutes=120))
    removed = await backend.prune(datetime.now(tz=UTC))
    eq(removed, 1)
    eq(await backend.list_checkpoints(), [])
    await backend.close()


def test_backends_satisfy_the_protocol() -> None:
    ok(isinstance(MemoryStateBackend(), StateBackend))
    ok(isinstance(SqliteStateBackend(Path("unused.db")), StateBackend))
    ok(isinstance(MariaDBStateBackend("mysql://root@127.0.0.1/db"), StateBackend))
