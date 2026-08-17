"""Integration tests for the MariaDB backend against a real ephemeral server."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from mispfleet.exceptions import StateError
from mispfleet.settings import StateSettings, build_state_backend
from mispfleet.state import MariaDBStateBackend, SqliteStateBackend
from mispfleet.state.mariadb import load_mariadb_module
from tests.state_lifecycle import exercise_backend, operation, wipe
from tests.support import contains, eq, not_contains, ok


async def test_mariadb_backend_full_lifecycle(mariadb_dsn: str) -> None:
    await exercise_backend(MariaDBStateBackend(mariadb_dsn))


async def test_mariadb_backend_persists_across_connections(mariadb_dsn: str) -> None:
    first = MariaDBStateBackend(mariadb_dsn)
    await first.initialize()
    await wipe(first)
    record = operation()
    await first.save_operation(record)
    await first.close()
    second = MariaDBStateBackend(mariadb_dsn)
    await second.initialize()
    operations = await second.list_operations()
    eq([o.operation_id for o in operations], [record.operation_id])
    await wipe(second)
    await second.close()


async def test_mariadb_backend_requires_initialization(mariadb_dsn: str) -> None:
    backend = MariaDBStateBackend(mariadb_dsn)
    with pytest.raises(StateError):
        await backend.list_operations()
    await backend.close()


async def test_mariadb_backend_reports_unknown_checkpoint(mariadb_dsn: str) -> None:
    backend = MariaDBStateBackend(mariadb_dsn)
    await backend.initialize()
    with pytest.raises(StateError) as excinfo:
        await backend.load_checkpoint(uuid4())
    contains(str(excinfo.value), "unknown checkpoint")
    await backend.close()


def test_mariadb_dsn_parsing_and_redaction() -> None:
    backend = MariaDBStateBackend("mysql://analyst:hunter2@db.example:3307/fleetstate")
    eq(backend.location, "mysql://analyst@db.example:3307/fleetstate")
    not_contains(backend.location, "hunter2")
    defaults = MariaDBStateBackend("mariadb://db.example")
    eq(defaults.location, "mysql://root@db.example:3306/mispfleet")
    resolved_value = "from-env"
    explicit = MariaDBStateBackend("mysql://db.example/other", password=resolved_value)
    eq(explicit.location, "mysql://root@db.example:3306/other")
    with pytest.raises(StateError) as excinfo:
        MariaDBStateBackend("postgres://db.example/state")
    contains(str(excinfo.value), "postgres")


async def test_mariadb_connect_failure_is_a_state_error() -> None:
    backend = MariaDBStateBackend("mysql://root@127.0.0.1:9/mispfleet_test")
    with pytest.raises(StateError) as excinfo:
        await backend.initialize()
    contains(str(excinfo.value), "cannot connect")
    await backend.close()


async def test_mariadb_missing_driver_reports_the_extra() -> None:
    backend = MariaDBStateBackend(
        "mysql://root@127.0.0.1/db", module_name=f"missing_driver_{uuid4().hex}"
    )
    with pytest.raises(StateError) as excinfo:
        await backend.initialize()
    contains(str(excinfo.value), "mispfleet[mariadb]")


def test_load_mariadb_module_returns_real_driver() -> None:
    import pymysql

    eq(load_mariadb_module("pymysql"), pymysql)


def test_build_state_backend_selects_the_configured_backend(tmp_path: Path) -> None:
    sqlite_default = build_state_backend(StateSettings())
    ok(isinstance(sqlite_default, SqliteStateBackend))
    sqlite_custom = build_state_backend(StateSettings(path=tmp_path / "s.db"))
    eq(sqlite_custom.location, str(tmp_path / "s.db"))
    mariadb = build_state_backend(
        StateSettings(backend="mariadb", dsn="mysql://root@db.example/fleet")
    )
    ok(isinstance(mariadb, MariaDBStateBackend))
    with pytest.raises(Exception) as excinfo:
        StateSettings(backend="mariadb")
    contains(str(excinfo.value), "requires a dsn")


def test_build_state_backend_reads_password_from_environment(tmp_path: Path) -> None:
    import os

    variable = f"MISPFLEET_STATE_PW_{uuid4().hex.upper()}"
    os.environ[variable] = "env-secret"
    try:
        backend = build_state_backend(
            StateSettings(
                backend="mariadb",
                dsn="mysql://root@db.example/fleet",
                password_env=variable,
            )
        )
    finally:
        del os.environ[variable]
    ok(isinstance(backend, MariaDBStateBackend))
    not_contains(backend.location, "env-secret")


async def test_mariadb_query_failures_become_state_errors(mariadb_dsn: str) -> None:
    saboteur = MariaDBStateBackend(mariadb_dsn)
    await saboteur.initialize()
    victim = MariaDBStateBackend(mariadb_dsn)
    await victim.initialize()
    await saboteur._execute("DROP TABLE checkpoints")
    try:
        with pytest.raises(StateError) as excinfo:
            await victim.list_checkpoints()
        contains(str(excinfo.value), "MariaDB error")
        not_contains(str(excinfo.value), "hunter2")
    finally:
        await saboteur._execute(
            "CREATE TABLE IF NOT EXISTS checkpoints ("
            " checkpoint_id VARCHAR(36) PRIMARY KEY,"
            " updated_at VARCHAR(40) NOT NULL,"
            " payload MEDIUMTEXT NOT NULL)"
        )
        await saboteur.close()
        await victim.close()


async def test_mariadb_round_trips_non_ascii_payloads(mariadb_dsn: str) -> None:
    backend = MariaDBStateBackend(mariadb_dsn)
    await backend.initialize()
    await wipe(backend)
    # A latin1 column would store these as '?' under a non-strict SQL mode and
    # reject them under a strict one; the schema pins utf8mb4 for both.
    message = "fallo: контроль 🌍 τεστ"
    record = operation().model_copy(update={"error": message})
    await backend.save_operation(record)
    stored = await backend.list_operations()
    eq([o.error for o in stored], [message])
    await wipe(backend)
    await backend.close()


async def test_mariadb_prune_rolls_back_as_one_transaction(mariadb_dsn: str) -> None:
    saboteur = MariaDBStateBackend(mariadb_dsn)
    await saboteur.initialize()
    victim = MariaDBStateBackend(mariadb_dsn)
    await victim.initialize()
    await wipe(victim)
    stale = operation(age_minutes=120)
    await victim.save_operation(stale)
    # queries is pruned last, so the operations DELETE has already run when it
    # fails: without a transaction the audit record would be gone for good.
    await saboteur._execute("DROP TABLE queries")
    try:
        with pytest.raises(StateError):
            await victim.prune(datetime.now(tz=UTC) - timedelta(minutes=60))
        eq([o.operation_id for o in await victim.list_operations()], [stale.operation_id])
    finally:
        await saboteur._execute(
            "CREATE TABLE IF NOT EXISTS queries ("
            " id BIGINT AUTO_INCREMENT PRIMARY KEY,"
            " fingerprint VARCHAR(64) NOT NULL,"
            " executed_at VARCHAR(40) NOT NULL,"
            " payload MEDIUMTEXT NOT NULL)"
            " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        await wipe(victim)
        await saboteur.close()
        await victim.close()


async def test_cancelling_a_statement_leaves_the_connection_usable(mariadb_dsn: str) -> None:
    """A cancelled call must not release the lock while its thread still runs.

    asyncio.to_thread cannot be interrupted and PyMySQL connections are not
    thread-safe, so the next caller would interleave packets on the same
    socket with the abandoned statement.
    """
    import asyncio

    backend = MariaDBStateBackend(mariadb_dsn)
    await backend.initialize()
    await wipe(backend)
    try:
        slow = asyncio.ensure_future(backend._execute("SELECT SLEEP(1)"))
        await asyncio.sleep(0.1)
        slow.cancel()
        with pytest.raises(asyncio.CancelledError):
            await slow
        record = operation()
        await backend.save_operation(record)
        eq([o.operation_id for o in await backend.list_operations()], [record.operation_id])
    finally:
        await wipe(backend)
        await backend.close()
