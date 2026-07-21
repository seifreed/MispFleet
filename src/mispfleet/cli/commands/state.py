"""Local state commands."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

import typer
from rich.console import Console

from mispfleet.cli.context import EXIT_SUCCESS, CLIState, parse_duration, run, state_of
from mispfleet.settings import default_state_path
from mispfleet.state.sqlite import SqliteStateBackend

app = typer.Typer(help="Inspect and prune local state.")
checkpoint_app = typer.Typer(help="Manage checkpoints.")
app.add_typer(checkpoint_app, name="checkpoint")


async def _with_backend(state: CLIState) -> SqliteStateBackend:
    backend = SqliteStateBackend(default_state_path())
    await backend.initialize()
    return backend


@app.command()
def info(ctx: typer.Context) -> None:
    """Show the state database location and record counts."""
    state = state_of(ctx)

    async def inner() -> int:
        backend = await _with_backend(state)
        try:
            checkpoints = await backend.list_checkpoints()
            operations = await backend.list_operations()
        finally:
            await backend.close()
        payload = {
            "path": str(backend.path),
            "checkpoints": len(checkpoints),
            "operations": len(operations),
        }
        state.emit(
            "state-info",
            payload,
            render=lambda console: console.print(
                f"{backend.path}: {len(checkpoints)} checkpoint(s), "
                f"{len(operations)} operation(s)"
            ),
        )
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def checkpoints(ctx: typer.Context) -> None:
    """List stored checkpoints."""
    state = state_of(ctx)

    async def inner() -> int:
        backend = await _with_backend(state)
        try:
            stored = await backend.list_checkpoints()
        finally:
            await backend.close()

        def render(console: Console) -> None:
            for checkpoint in stored:
                console.print(
                    f"{checkpoint.checkpoint_id} {checkpoint.server} "
                    f"page={checkpoint.page} records={checkpoint.record_count}"
                )

        state.emit("state-checkpoints", {"checkpoints": stored}, render=render)
        return EXIT_SUCCESS

    run(state, inner())


@checkpoint_app.command("show")
def checkpoint_show(ctx: typer.Context, checkpoint_id: Annotated[str, typer.Argument()]) -> None:
    """Show one checkpoint."""
    state = state_of(ctx)

    async def inner() -> int:
        backend = await _with_backend(state)
        try:
            checkpoint = await backend.load_checkpoint(UUID(checkpoint_id))
        finally:
            await backend.close()
        state.emit(
            "state-checkpoint",
            checkpoint,
            render=lambda console: console.print_json(data=checkpoint.model_dump(mode="json")),
        )
        return EXIT_SUCCESS

    run(state, inner())


@checkpoint_app.command("delete")
def checkpoint_delete(ctx: typer.Context, checkpoint_id: Annotated[str, typer.Argument()]) -> None:
    """Delete one checkpoint."""
    state = state_of(ctx)

    async def inner() -> int:
        backend = await _with_backend(state)
        try:
            await backend.delete_checkpoint(UUID(checkpoint_id))
        finally:
            await backend.close()
        typer.echo(f"deleted checkpoint {checkpoint_id}")
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def operations(ctx: typer.Context) -> None:
    """List recorded operations."""
    state = state_of(ctx)

    async def inner() -> int:
        backend = await _with_backend(state)
        try:
            stored = await backend.list_operations()
        finally:
            await backend.close()

        def render(console: Console) -> None:
            for operation in stored:
                console.print(
                    f"{operation.operation_id} {operation.kind} "
                    f"{operation.source_server}->{operation.destination_server} "
                    f"{operation.result}"
                )

        state.emit("state-operations", {"operations": stored}, render=render)
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def prune(
    ctx: typer.Context,
    older_than: Annotated[str, typer.Option(help="Age threshold, e.g. 30d.")],
) -> None:
    """Delete state records older than the given age."""
    state = state_of(ctx)
    threshold = datetime.now(tz=UTC) - parse_duration(older_than)

    async def inner() -> int:
        backend = await _with_backend(state)
        try:
            removed = await backend.prune(threshold)
        finally:
            await backend.close()
        state.emit(
            "state-prune",
            {"removed": removed},
            render=lambda console: console.print(f"removed {removed} record(s)"),
        )
        return EXIT_SUCCESS

    run(state, inner())
