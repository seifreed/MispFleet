"""Local state commands."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

import typer
from rich.console import Console

from mispfleet.cli.context import EXIT_SUCCESS, run, since_to_datetime, state_of
from mispfleet.output.renderers import plain_text

app = typer.Typer(help="Inspect and prune local state.")
checkpoint_app = typer.Typer(help="Manage checkpoints.")
app.add_typer(checkpoint_app, name="checkpoint")


@app.command()
def info(ctx: typer.Context) -> None:
    """Show the state database location and record counts."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.open_backend() as backend:
            checkpoints = await backend.list_checkpoints()
            operations = await backend.list_operations()
            plans = await backend.list_plans()
            queries = await backend.list_queries()
            plugins = await backend.list_plugins()
        payload = {
            "location": backend.location,
            "checkpoints": len(checkpoints),
            "operations": len(operations),
            "plans": len(plans),
            "queries": len(queries),
            "plugins": len(plugins),
        }
        state.emit(
            "state-info",
            payload,
            render=lambda console: console.print(
                f"{plain_text(backend.location)}: {len(checkpoints)} checkpoint(s), "
                f"{len(operations)} operation(s), {len(plans)} plan(s), "
                f"{len(queries)} query fingerprint(s), {len(plugins)} plugin(s)"
            ),
        )
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def checkpoints(ctx: typer.Context) -> None:
    """List stored checkpoints."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.open_backend() as backend:
            stored = await backend.list_checkpoints()

        def render(console: Console) -> None:
            for checkpoint in stored:
                console.print(
                    f"{plain_text(checkpoint.checkpoint_id)} {plain_text(checkpoint.server)} "
                    f"page={checkpoint.page} records={checkpoint.record_count}"
                )

        state.emit("state-checkpoints", {"checkpoints": stored}, render=render)
        return EXIT_SUCCESS

    run(state, inner())


def _checkpoint_uuid(raw: str) -> UUID:
    """Parse a checkpoint identifier, reporting a bad value as a usage error."""
    try:
        return UUID(raw)
    except ValueError as error:
        raise typer.BadParameter(f"invalid checkpoint id {raw!r}") from error


@checkpoint_app.command("show")
def checkpoint_show(ctx: typer.Context, checkpoint_id: Annotated[str, typer.Argument()]) -> None:
    """Show one checkpoint."""
    state = state_of(ctx)
    identifier = _checkpoint_uuid(checkpoint_id)

    async def inner() -> int:
        async with state.open_backend() as backend:
            checkpoint = await backend.load_checkpoint(identifier)
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
    identifier = _checkpoint_uuid(checkpoint_id)

    async def inner() -> int:
        async with state.open_backend() as backend:
            await backend.delete_checkpoint(identifier)
        typer.echo(f"deleted checkpoint {checkpoint_id}")
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def operations(ctx: typer.Context) -> None:
    """List recorded operations."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.open_backend() as backend:
            stored = await backend.list_operations()

        def render(console: Console) -> None:
            for operation in stored:
                console.print(
                    f"{plain_text(operation.operation_id)} {plain_text(operation.kind)} "
                    f"{plain_text(operation.source_server)}->"
                    f"{plain_text(operation.destination_server)} "
                    f"{plain_text(operation.result)}"
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
    threshold = since_to_datetime(older_than)

    async def inner() -> int:
        async with state.open_backend() as backend:
            removed = await backend.prune(threshold)
        state.emit(
            "state-prune",
            {"removed": removed},
            render=lambda console: console.print(f"removed {removed} record(s)"),
        )
        return EXIT_SUCCESS

    run(state, inner())
