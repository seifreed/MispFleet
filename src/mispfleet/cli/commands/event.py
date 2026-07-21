"""Event commands: retrieval, comparison, copy and validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError as PydanticValidationError
from rich.console import Console

from mispfleet.cli.context import (
    EXIT_NO_MATCHES,
    EXIT_PLAN,
    EXIT_POLICY,
    EXIT_SUCCESS,
    EXIT_USAGE,
    CLIState,
    run,
    state_of,
)
from mispfleet.fleet import ServerSelector
from mispfleet.models.event import MISPEvent
from mispfleet.models.plan import ConflictAction, CopyPlan
from mispfleet.output.renderers import render_apply_result, render_diff, render_plan
from mispfleet.output.serializers import document, serialize
from mispfleet.settings import default_state_path
from mispfleet.state.sqlite import SqliteStateBackend

app = typer.Typer(help="Work with events across the fleet.")


def _single_server(state: CLIState) -> str:
    if len(state.servers) == 1:
        return state.servers[0]
    raise typer.BadParameter("specify exactly one server with --server NAME")


@app.command()
def get(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
) -> None:
    """Fetch one event from one server (--server NAME)."""
    state = state_of(ctx)
    server = _single_server(state)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            event = await fleet.client(server).events.get(event_id)
        state.emit(
            "event-get",
            {"server": server, "event": event},
            render=lambda console: console.print_json(data=event.model_dump(mode="json")),
        )
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def find(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
) -> None:
    """Locate an event across the selected servers."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            result = await fleet.get_event(event_id, state.selector() or ServerSelector.all())
        found = {name: event.info for name, event in result.results.items()}
        missing = result.failed_servers

        def render(console: Console) -> None:
            for name, info in found.items():
                console.print(f"[green]found[/green] {name}: {info}")
            for name in missing:
                console.print(f"[yellow]absent[/yellow] {name}")

        state.emit("event-find", {"found": found, "missing": missing}, render=render)
        return EXIT_SUCCESS if found else EXIT_NO_MATCHES

    run(state, inner())


@app.command()
def diff(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
    left: Annotated[str, typer.Option("--left", help="Left server.")],
    right: Annotated[str, typer.Option("--right", help="Right server.")],
) -> None:
    """Compare one event between two servers."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            result = await fleet.compare_event(event_id, left, right)
        state.emit(
            "event-diff",
            result,
            render=lambda console: render_diff(console, result),
        )
        return EXIT_SUCCESS

    run(state, inner())


def _plan_exit_code(plan: CopyPlan) -> int:
    if not plan.blocking_errors:
        return EXIT_SUCCESS
    if any(issue.code == "policy-violation" for issue in plan.blocking_errors):
        return EXIT_POLICY
    return EXIT_PLAN


@app.command()
def copy(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
    source: Annotated[str, typer.Option("--from", help="Source server.")],
    destination: Annotated[str, typer.Option("--to", help="Destination server.")],
    policy: Annotated[str | None, typer.Option(help="Policy applied before copying.")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Plan only, never mutate.")] = False,
    on_conflict: Annotated[
        ConflictAction,
        typer.Option(help="Behavior when the destination already has the event."),
    ] = ConflictAction.ABORT,
    plan_output: Annotated[
        Path | None, typer.Option(help="Write the generated plan to this file.")
    ] = None,
) -> None:
    """Copy one event between servers through an explicit plan."""
    state = state_of(ctx)

    async def inner() -> int:
        backend = SqliteStateBackend(default_state_path())
        await backend.initialize()
        try:
            async with state.build_fleet(state_backend=backend) as fleet:
                plan = await fleet.plan_copy(
                    event_id, source, destination, policy=policy, on_conflict=on_conflict
                )
                if plan_output is not None:
                    plan_output.write_text(
                        serialize(document("copy-plan", plan), "json"), encoding="utf-8"
                    )
                state.emit(
                    "copy-plan",
                    plan,
                    render=lambda console: render_plan(console, plan),
                )
                code = _plan_exit_code(plan)
                if dry_run or plan_output is not None or code != EXIT_SUCCESS:
                    return code
                result = await fleet.apply(plan)
                state.emit(
                    "copy-apply",
                    result,
                    render=lambda console: render_apply_result(console, result),
                )
                return EXIT_SUCCESS
        finally:
            await backend.close()

    run(state, inner())


@app.command()
def export(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
) -> None:
    """Export one event as a machine-readable document (--server NAME)."""
    state = state_of(ctx)
    server = _single_server(state)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            event = await fleet.client(server).events.get(event_id)
        state.emit(
            "event-export",
            {"server": server, "event": event},
            render=lambda console: console.print_json(data=event.model_dump(mode="json")),
        )
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def validate(
    ctx: typer.Context,
    file: Annotated[Path, typer.Argument(help="Path to a MISP event JSON file.")],
) -> None:
    """Validate a local event file against the normalized model."""
    state = state_of(ctx)
    try:
        raw = json.loads(file.read_text(encoding="utf-8"))
        event = MISPEvent.from_misp(raw)
    except (OSError, ValueError, KeyError, PydanticValidationError) as error:
        typer.echo(f"invalid event file: {error}", err=True)
        raise typer.Exit(EXIT_USAGE) from error
    state.emit(
        "event-validate",
        {"valid": True, "uuid": event.uuid, "fingerprint": event.canonical_fingerprint()},
        render=lambda console: console.print(f"event {event.uuid} is valid"),
    )
