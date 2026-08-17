"""Event commands: retrieval, comparison, copy and validation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError as PydanticValidationError
from rich.console import Console
from typer._click.core import Command as ClickCommand
from typer._click.core import Context as ClickContext
from typer.core import TyperGroup

from mispfleet.cli.context import (
    EXIT_NO_MATCHES,
    EXIT_PARTIAL,
    EXIT_PLAN,
    EXIT_POLICY,
    EXIT_SUCCESS,
    EXIT_USAGE,
    run,
    state_of,
    write_output_file,
)
from mispfleet.exceptions import InvalidResponseError
from mispfleet.fleet import ServerSelector
from mispfleet.models.event import MISPEvent
from mispfleet.models.plan import ConflictAction, CopyPlan
from mispfleet.output.renderers import (
    patch_from_diff,
    plain_text,
    render_apply_result,
    render_diff,
    render_plan,
)
from mispfleet.output.serializers import document, serialize

app = typer.Typer(help="Work with events across the fleet.")


class CopyGroup(TyperGroup):
    """Routes ``copy plan ...`` to the subcommand and anything else to ``run``.

    Typer cannot expose a command and a group under the same name, so the
    plain ``event copy EVENT`` form is dispatched to a hidden default
    subcommand. An event whose identifier is literally ``plan`` would be read
    as the subcommand; MISP identifiers are UUIDs or numeric ids.
    """

    def resolve_command(
        self, ctx: ClickContext, args: list[str]
    ) -> tuple[str | None, ClickCommand | None, list[str]]:
        """Insert the default subcommand when the first argument is not one."""
        if args and args[0] not in self.commands:
            args = ["run", *args]
        return super().resolve_command(ctx, args)


copy_app = typer.Typer(cls=CopyGroup, help="Copy one event between servers.")
app.add_typer(copy_app, name="copy")


@app.command()
def get(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
) -> None:
    """Fetch one event from one server (--server NAME)."""
    state = state_of(ctx)
    server = state.single_server()

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
        # A server that could not answer has not said the event is absent.
        # Reporting both as "absent" turned an outage into a confident "this
        # event does not exist anywhere", with exit 11 to match.
        missing = sorted(name for name, error in result.errors.items() if error.status_code == 404)
        unreachable = {
            name: error.message for name, error in result.errors.items() if name not in missing
        }

        def render(console: Console) -> None:
            for name, info in found.items():
                console.print(f"[green]found[/green] {plain_text(name)}: {plain_text(info)}")
            for name in missing:
                console.print(f"[yellow]absent[/yellow] {plain_text(name)}")
            for name, message in unreachable.items():
                console.print(f"[red]failed[/red] {plain_text(name)}: {plain_text(message)}")

        state.emit(
            "event-find",
            {"found": found, "missing": missing, "failed": unreachable},
            render=render,
            # Every sibling marks the envelope partial when a server could not
            # answer, so a machine reader does not have to infer it from the
            # exit code it may never see.
            partial=bool(unreachable),
        )
        if unreachable:
            # Every other command reports a server it could not reach as
            # partial whether or not the rest answered; finding the event on
            # one server says nothing about the one that never replied.
            return EXIT_PARTIAL
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
            patch_text=lambda: patch_from_diff(result),
        )
        return EXIT_SUCCESS

    run(state, inner())


def _plan_exit_code(plan: CopyPlan) -> int:
    if not plan.blocking_errors:
        return EXIT_SUCCESS
    if any(issue.code == "policy-violation" for issue in plan.blocking_errors):
        return EXIT_POLICY
    return EXIT_PLAN


@copy_app.command("run", hidden=True)
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
        async with state.fleet_session() as fleet:
            plan = await fleet.plan_copy(
                event_id, source, destination, policy=policy, on_conflict=on_conflict
            )
            if plan_output is not None:
                write_output_file(plan_output, serialize(document("copy-plan", plan), "json"))
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

    run(state, inner())


@copy_app.command("plan")
def copy_plan(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
    source: Annotated[str, typer.Option("--from", help="Source server.")],
    destination: Annotated[str, typer.Option("--to", help="Destination server.")],
    policy: Annotated[str | None, typer.Option(help="Policy applied before copying.")] = None,
    on_conflict: Annotated[
        ConflictAction,
        typer.Option(help="Behavior when the destination already has the event."),
    ] = ConflictAction.ABORT,
) -> None:
    """Generate a copy plan without mutating the destination.

    The plan is written to the global ``--output`` path when given, so it can
    be reviewed and later applied with ``mispfleet apply PLAN_FILE``.
    """
    state = state_of(ctx)

    async def inner() -> int:
        async with state.fleet_session() as fleet:
            plan = await fleet.plan_copy(
                event_id, source, destination, policy=policy, on_conflict=on_conflict
            )
        if state.output_path is not None:
            write_output_file(state.output_path, serialize(document("copy-plan", plan), "json"))
        else:
            state.emit("copy-plan", plan, render=lambda console: render_plan(console, plan))
        return _plan_exit_code(plan)

    run(state, inner())


@app.command()
def export(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
) -> None:
    """Export one event as a machine-readable document (--server NAME)."""
    state = state_of(ctx)
    server = state.single_server()

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
        raw = json.loads(file.read_text(encoding="utf-8-sig"))
        event = MISPEvent.from_misp(raw)
    except (OSError, ValueError, KeyError, PydanticValidationError, InvalidResponseError) as error:
        typer.echo(f"invalid event file: {error}", err=True)
        raise typer.Exit(EXIT_USAGE) from error
    state.emit(
        "event-validate",
        {"valid": True, "uuid": event.uuid, "fingerprint": event.canonical_fingerprint()},
        render=lambda console: console.print(f"event {plain_text(event.uuid)} is valid"),
    )
