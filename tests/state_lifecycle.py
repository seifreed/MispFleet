"""Shared state-backend lifecycle exercise, reused by every backend's tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest

from mispfleet.exceptions import StateError
from mispfleet.state.base import (
    CapabilityRecord,
    Checkpoint,
    OperationRecord,
    PlanRecord,
    PluginRecord,
    QueryRecord,
    StateBackend,
)
from tests.support import eq, not_none, ok


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


def plan_record(age_minutes: int = 0) -> PlanRecord:
    """Build a plan metadata record aged ``age_minutes`` into the past."""
    return PlanRecord(
        plan_id=uuid4(),
        kind="copy",
        schema_version="1.0",
        fingerprint="plan-fp",
        source_server="research",
        destination_server="production",
        event_identifier="9c5c1c2e-0000-4000-8000-00000000000e",
        policy="production-import",
        on_conflict="abort",
        generated_at=datetime.now(tz=UTC) - timedelta(minutes=age_minutes),
        transformations=2,
        validations=3,
    )


def query_record(age_minutes: int = 0) -> QueryRecord:
    """Build a query fingerprint record aged ``age_minutes`` into the past."""
    return QueryRecord(
        fingerprint="query-fp",
        operation="federated-search",
        servers=["research", "production"],
        executed_at=datetime.now(tz=UTC) - timedelta(minutes=age_minutes),
        record_count=42,
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
    old_plan = plan_record(age_minutes=120)
    new_plan = plan_record(age_minutes=0)
    await backend.save_plan(old_plan)
    await backend.save_plan(new_plan)
    plans = await backend.list_plans()
    eq([p.plan_id for p in plans], [new_plan.plan_id, old_plan.plan_id])
    eq(plans[0].transformations, 2)
    updated_plan = new_plan.model_copy(update={"blocking_errors": 5})
    await backend.save_plan(updated_plan)
    eq((await backend.list_plans())[0].blocking_errors, 5)
    await backend.save_query(query_record(age_minutes=120))
    await backend.save_query(query_record(age_minutes=0))
    queries = await backend.list_queries()
    eq(len(queries), 2)
    eq(queries[0].fingerprint, "query-fp")
    eq(queries[0].servers, ["research", "production"])
    removed = await backend.prune(datetime.now(tz=UTC) - timedelta(minutes=60))
    eq(removed, 3)
    remaining = await backend.list_operations()
    eq([o.operation_id for o in remaining], [new_operation.operation_id])
    eq([p.plan_id for p in await backend.list_plans()], [new_plan.plan_id])
    eq(len(await backend.list_queries()), 1)
    await exercise_capability_cache(backend)
    await exercise_plugin_records(backend)
    await exercise_timezone_independence(backend)
    await exercise_equal_timestamp_ordering(backend)
    await exercise_snapshot_isolation(backend)
    await exercise_driver_errors_are_typed(backend)
    await backend.close()


async def exercise_plugin_records(backend: StateBackend) -> None:
    """Run the plugin-metadata lifecycle against a live backend."""
    eq(await backend.list_plugins(), [])
    now = datetime.now(tz=UTC)
    await backend.save_plugin(
        PluginRecord(name="beta", target="pkg.beta:Plugin", discovered_at=now)
    )
    await backend.save_plugin(
        PluginRecord(
            name="alpha",
            target="pkg.alpha:Plugin",
            discovered_at=now,
            version="1.2.0",
            category="exporter",
            compatible_with=">=0.1",
        )
    )
    plugins = await backend.list_plugins()
    eq([p.name for p in plugins], ["alpha", "beta"])
    eq(plugins[0].version, "1.2.0")
    eq(plugins[1].version, None)
    await backend.save_plugin(
        PluginRecord(name="alpha", target="pkg.alpha:Renamed", discovered_at=now)
    )
    refreshed = await backend.list_plugins()
    eq(len(refreshed), 2)
    eq(refreshed[0].target, "pkg.alpha:Renamed")


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


async def exercise_timezone_independence(backend: StateBackend) -> None:
    """Ordering and pruning must follow the instant, not the printed offset.

    Backends that store ``isoformat()`` verbatim compare mixed-offset strings
    lexicographically: a record written from a +02:00 machine then sorts ahead
    of a newer UTC one and survives a prune that should remove it.
    """
    await wipe(backend)
    east = timezone(timedelta(hours=2))
    now = datetime.now(tz=UTC).replace(microsecond=0)
    older = checkpoint().model_copy(
        update={
            "checkpoint_id": uuid4(),
            "updated_at": (now - timedelta(hours=2)).astimezone(east),
        }
    )
    newer = checkpoint().model_copy(update={"checkpoint_id": uuid4(), "updated_at": now})
    await backend.save_checkpoint(older)
    await backend.save_checkpoint(newer)
    listed = await backend.list_checkpoints()
    eq([c.checkpoint_id for c in listed], [newer.checkpoint_id, older.checkpoint_id])
    eq(await backend.prune(now - timedelta(hours=1)), 1)
    eq([c.checkpoint_id for c in await backend.list_checkpoints()], [newer.checkpoint_id])
    naive = checkpoint().model_copy(
        update={
            "checkpoint_id": uuid4(),
            "updated_at": (now - timedelta(hours=3)).replace(tzinfo=None),
        }
    )
    await backend.save_checkpoint(naive)
    ordered = await backend.list_checkpoints()
    eq([c.checkpoint_id for c in ordered], [newer.checkpoint_id, naive.checkpoint_id])
    await wipe(backend)


async def exercise_snapshot_isolation(backend: StateBackend) -> None:
    """Save and load both hand out snapshots: mutating either changes nothing."""
    await wipe(backend)
    record = checkpoint(page=3)
    await backend.save_checkpoint(record)
    record.page = 99
    eq((await backend.load_checkpoint(record.checkpoint_id)).page, 3)

    # The durable backends re-parse JSON on every read, so a caller that tweaks
    # a loaded record before deciding whether to persist it must not rewrite
    # stored state on the in-memory backend either.
    loaded = await backend.load_checkpoint(record.checkpoint_id)
    loaded.page = 77
    eq((await backend.load_checkpoint(record.checkpoint_id)).page, 3)
    listed = await backend.list_checkpoints()
    listed[0].page = 55
    eq((await backend.load_checkpoint(record.checkpoint_id)).page, 3)

    capabilities = CapabilityRecord(
        server="alpha", capabilities={"events"}, fetched_at=datetime.now(tz=UTC)
    )
    await backend.save_capabilities(capabilities)
    cached = await backend.load_capabilities("alpha")
    not_none(cached).capabilities.add("injected")
    eq(not_none(await backend.load_capabilities("alpha")).capabilities, {"events"})
    await wipe(backend)


async def exercise_driver_errors_are_typed(backend: StateBackend) -> None:
    """Driver failures surface as ``StateError``, never as a raw DB-API error."""
    await wipe(backend)
    record = operation()
    await backend.save_operation(record)
    # operation_id is the primary key on both durable backends; a retry of the
    # same audit record must not escape as sqlite3.IntegrityError/MySQLError.
    raised = False
    try:
        await backend.save_operation(record)
    except StateError:
        raised = True
    ok(raised, "duplicate save_operation must raise StateError")
    await wipe(backend)


async def exercise_equal_timestamp_ordering(backend: StateBackend) -> None:
    """Records sharing a timestamp must come back in the same order everywhere.

    SQLite and memory broke the tie on the identifier; MariaDB ordered by the
    timestamp alone and left equal rows to the filesort, so the three backends
    disagreed on a list the contract calls deterministic.
    """
    await wipe(backend)
    moment = datetime.now(tz=UTC)
    ids = sorted(uuid4() for _ in range(3))
    for checkpoint_id in ids:
        await backend.save_checkpoint(
            checkpoint().model_copy(update={"checkpoint_id": checkpoint_id, "updated_at": moment})
        )
    eq(
        [record.checkpoint_id for record in await backend.list_checkpoints()],
        sorted(ids, reverse=True),
    )

    operation_ids = sorted(uuid4() for _ in range(3))
    for operation_id in operation_ids:
        await backend.save_operation(
            operation().model_copy(update={"operation_id": operation_id, "timestamp": moment})
        )
    eq(
        [record.operation_id for record in await backend.list_operations()],
        sorted(operation_ids, reverse=True),
    )
    await wipe(backend)
