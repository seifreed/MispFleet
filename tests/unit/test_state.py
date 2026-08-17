"""Unit tests for state backends; SQLite runs against real temporary files."""

from __future__ import annotations

import sqlite3
import stat
import sys
import threading
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from mispfleet.exceptions import StateError
from mispfleet.state import (
    MariaDBStateBackend,
    MemoryStateBackend,
    SqliteStateBackend,
    StateBackend,
)
from mispfleet.state.base import PluginRecord
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
    # POSIX enforces owner-only via the file mode; on Windows the file inherits
    # the user-profile directory's ACL, so we only assert it was created.
    if sys.platform == "win32":
        ok(backend.path.exists())
    else:
        eq(stat.S_IMODE(backend.path.stat().st_mode), 0o600)
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


async def test_sqlite_file_is_owner_only_from_creation(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "state.db"
    backend = SqliteStateBackend(path)
    await backend.initialize()
    try:
        if sys.platform == "win32":
            ok(path.exists())
        else:
            eq(path.stat().st_mode & 0o777, 0o600)
    finally:
        await backend.close()


async def test_sqlite_prune_compares_instants_not_printed_offsets(tmp_path: Path) -> None:
    backend = SqliteStateBackend(tmp_path / "state.db")
    await backend.initialize()
    try:
        # Written from a +02:00 clock: lexicographically "later" than the UTC
        # threshold although the instant it represents is older.
        stale = datetime(2026, 1, 1, 4, 0, tzinfo=timezone(timedelta(hours=2)))
        record = operation()
        await backend.save_operation(record.model_copy(update={"timestamp": stale}))
        removed = await backend.prune(datetime(2026, 1, 1, 3, 0, tzinfo=UTC))
        eq(removed, 1)
        eq(await backend.list_operations(), [])
    finally:
        await backend.close()


async def test_initialize_closes_the_connection_when_the_schema_fails(tmp_path: Path) -> None:
    """aiosqlite's worker is a non-daemon thread.

    Leaving it running after a failed schema step hung the interpreter at
    exit, so a corrupt state file hung the CLI instead of reporting an error.
    """
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"this is definitely not a sqlite database" * 8)
    # Delta against a baseline: Windows' event loop keeps extra worker threads
    # alive, so the absolute count is not 1 there — the invariant is that the
    # failed initialize leaks none of its own.
    baseline = threading.active_count()
    backend = SqliteStateBackend(corrupt)
    with pytest.raises(sqlite3.DatabaseError):
        await backend.initialize()
    eq(threading.active_count(), baseline)
    with pytest.raises(StateError):
        await backend.list_checkpoints()


async def test_sqlite_write_rolls_back_the_statements_that_already_ran(tmp_path: Path) -> None:
    """A failed multi-statement write must leave nothing behind.

    sqlite keeps executed statements in the connection's open implicit
    transaction, so without a rollback the next unrelated commit makes them
    durable — a half-applied prune, or a record whose caller saw an error.
    """
    backend = SqliteStateBackend(tmp_path / "rollback.db")
    await backend.initialize()
    try:
        with pytest.raises(StateError):
            await backend._write(
                [
                    (
                        "INSERT INTO checkpoints (checkpoint_id, updated_at, payload) "
                        "VALUES (?, ?, ?)",
                        ("orphan", "2026-01-01T00:00:00+00:00", "{}"),
                    ),
                    ("DELETE FROM table_that_does_not_exist", ()),
                ]
            )
        # A later, unrelated commit must not adopt the orphan row.
        await backend.save_plugin(
            PluginRecord(name="p", target="pkg:P", discovered_at=datetime.now(tz=UTC))
        )
        eq(await backend._read("SELECT checkpoint_id FROM checkpoints"), [])
    finally:
        await backend.close()
