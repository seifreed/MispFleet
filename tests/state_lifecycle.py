"""Shared state-backend lifecycle exercise, reused by every backend's tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from mispfleet.exceptions import StateError
from mispfleet.state.base import CapabilityRecord, Checkpoint, OperationRecord, StateBackend
from tests.support import eq, ok


def checkpoint(age_minutes: int = 0, page: int = 3) -> Checkpoint:
    """Build a realistic checkpoint aged ``age_minutes`` into the past."""
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
    """Build a realistic audit record aged ``age_minutes`` into the past."""
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


async def wipe(backend: StateBackend) -> None:
    """Remove every stored record so lifecycle runs start clean."""
    await backend.prune(datetime.now(tz=UTC) + timedelta(days=365))


async def exercise_backend(backend: StateBackend) -> None:
    """Run the full checkpoint + operation lifecycle against a live backend."""
    await backend.initialize()
    await wipe(backend)
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
    await exercise_capability_cache(backend)
    await backend.close()


async def exercise_capability_cache(backend: StateBackend) -> None:
    """Run the capability-cache lifecycle against a live backend."""
    now = datetime.now(tz=UTC)
    eq(await backend.load_capabilities("production"), None)
    record = CapabilityRecord(
        server="production",
        misp_version="2.4.190",
        capabilities={"rest-search", "events"},
        fetched_at=now,
        expires_at=now + timedelta(hours=1),
    )
    await backend.save_capabilities(record)
    loaded = await backend.load_capabilities("production")
    ok(loaded is not None)
    if loaded is None:
        return
    eq(loaded.misp_version, "2.4.190")
    eq(loaded.capabilities, {"rest-search", "events"})
    ok(not loaded.expired(now))
    ok(loaded.expired(now + timedelta(hours=2)))
    refreshed = record.model_copy(update={"misp_version": "2.5.0"})
    await backend.save_capabilities(refreshed)
    reloaded = await backend.load_capabilities("production")
    eq(reloaded.misp_version if reloaded else None, "2.5.0")
    await backend.invalidate_capabilities("production")
    await backend.invalidate_capabilities("production")
    eq(await backend.load_capabilities("production"), None)
