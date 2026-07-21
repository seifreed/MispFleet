"""Unit tests for state backends; SQLite runs against real temporary files."""

from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from mispfleet.exceptions import StateError
from mispfleet.state import (
    Checkpoint,
    MemoryStateBackend,
    OperationRecord,
    SqliteStateBackend,
    StateBackend,
)
from tests.support import eq, ok


def checkpoint(age_minutes: int = 0, page: int = 3) -> Checkpoint:
    moment = datetime.now(tz=UTC) - timedelta(minutes=age_minutes)
    return Checkpoint(
        checkpoint_id=uuid4(),
        operation_type="attribute-search",
        query_fingerprint="fp-1",
        server="production",
        page=page,
        last_entity_uuid="1f2b8a1e-0000-4000-8000-000000000001",
        record_count=page * 100,
        created_at=moment,
        updated_at=moment,
        client_version="0.1.0",
        server_version="2.4.190",
    )


def operation(age_minutes: int = 0) -> OperationRecord:
    return OperationRecord(
        operation_id=uuid4(),
        kind="copy-apply",
        timestamp=datetime.now(tz=UTC) - timedelta(minutes=age_minutes),
        source_server="research",
        destination_server="production",
        event_identifier="9c5c1c2e-0000-4000-8000-00000000000e",
        plan_fingerprint="plan-fp",
        policy="production-import",
        result="applied",
    )


async def exercise_backend(backend: StateBackend) -> None:
    await backend.initialize()
    first = checkpoint(age_minutes=120)
    second = checkpoint(age_minutes=0, page=9)
    await backend.save_checkpoint(first)
    await backend.save_checkpoint(second)
    loaded = await backend.load_checkpoint(first.checkpoint_id)
    eq(loaded.page, first.page)
    eq(loaded.query_fingerprint, "fp-1")
    listed = await backend.list_checkpoints()
    eq([c.checkpoint_id for c in listed], [second.checkpoint_id, first.checkpoint_id])
    updated = first.model_copy(update={"page": 5, "updated_at": datetime.now(tz=UTC)})
    await backend.save_checkpoint(updated)
    eq((await backend.load_checkpoint(first.checkpoint_id)).page, 5)
    await backend.delete_checkpoint(second.checkpoint_id)
    await backend.delete_checkpoint(second.checkpoint_id)
    eq(len(await backend.list_checkpoints()), 1)
    with pytest.raises(StateError):
        await backend.load_checkpoint(second.checkpoint_id)
    old_operation = operation(age_minutes=120)
    new_operation = operation(age_minutes=0)
    await backend.save_operation(old_operation)
    await backend.save_operation(new_operation)
    operations = await backend.list_operations()
    eq(
        [o.operation_id for o in operations],
        [new_operation.operation_id, old_operation.operation_id],
    )
    removed = await backend.prune(datetime.now(tz=UTC) - timedelta(minutes=60))
    eq(removed, 1)
    remaining = await backend.list_operations()
    eq([o.operation_id for o in remaining], [new_operation.operation_id])
    await backend.close()


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


def test_backends_satisfy_the_protocol() -> None:
    ok(isinstance(MemoryStateBackend(), StateBackend))
    ok(isinstance(SqliteStateBackend(Path("unused.db")), StateBackend))


async def test_memory_prune_removes_old_checkpoints() -> None:
    backend = MemoryStateBackend()
    await backend.initialize()
    await backend.save_checkpoint(checkpoint(age_minutes=120))
    removed = await backend.prune(datetime.now(tz=UTC))
    eq(removed, 1)
    eq(await backend.list_checkpoints(), [])
    await backend.close()
