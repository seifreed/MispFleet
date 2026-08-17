"""Policy commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from mispfleet.cli.context import (
    EXIT_POLICY,
    EXIT_SUCCESS,
    EXIT_USAGE,
    CLIState,
    guard,
    run,
    state_of,
)
from mispfleet.exceptions import InvalidResponseError
from mispfleet.models.event import MISPEvent
from mispfleet.output.renderers import plain_text
from mispfleet.policies.base import PolicyContext
from mispfleet.policies.engine import PolicyEngine

app = typer.Typer(help="Inspect and test governance policies.")


@app.command("list")
def list_policies(ctx: typer.Context) -> None:
    """List configured policies."""
    state = state_of(ctx)
    guard(state, lambda: _list_policies(state))


def _list_policies(state: CLIState) -> None:
    engine = PolicyEngine(state.load_config().policies)

    def render(console: Console) -> None:
        for name in engine.names():
            console.print(plain_text(name))

    state.emit("policy-list", {"policies": engine.names()}, render=render)


@app.command()
def show(ctx: typer.Context, name: Annotated[str, typer.Argument()]) -> None:
    """Show one policy definition."""
    state = state_of(ctx)

    def inner() -> None:
        policy = PolicyEngine(state.load_config().policies).get(name)
        payload = policy.spec.model_dump(mode="json")
        state.emit(
            "policy-show",
            {"name": name, "policy": payload},
            render=lambda console: console.print_json(data=payload),
        )

    guard(state, inner)


@app.command()
def validate(ctx: typer.Context, name: Annotated[str, typer.Argument()]) -> None:
    """Validate one policy definition."""
    state = state_of(ctx)

    def inner() -> None:
        PolicyEngine(state.load_config().policies).get(name)
        state.emit(
            "policy-validate",
            {"name": name, "valid": True},
            render=lambda console: console.print(f"policy {plain_text(repr(name))} is valid"),
        )

    guard(state, inner)


@app.command()
def test(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Policy name.")],
    event_file: Annotated[Path, typer.Argument(help="Path to a MISP event JSON file.")],
) -> None:
    """Evaluate one policy against a local event file."""
    state = state_of(ctx)
    try:
        event = MISPEvent.from_misp(json.loads(event_file.read_text(encoding="utf-8-sig")))
    except (OSError, ValueError, KeyError, InvalidResponseError) as error:
        typer.echo(f"invalid event file: {error}", err=True)
        raise typer.Exit(EXIT_USAGE) from error

    async def inner() -> int:
        engine = PolicyEngine(state.load_config().policies)
        context = PolicyContext(policy_name=name, source_server="local", destination_server="local")
        result = await engine.apply(name, context, event)

        def render(console: Console) -> None:
            console.print(f"accepted: {result.accepted}")
            for transformation in result.transformations:
                console.print(
                    f"  transform: {plain_text(transformation.action)} "
                    f"{plain_text(transformation.target)}"
                )
            for violation in result.violations:
                console.print(
                    f"  [red]violation[/red]: {plain_text(violation.rule)}: "
                    f"{plain_text(violation.message)}"
                )
            for warning in result.warnings:
                console.print(f"  [yellow]warning[/yellow]: {plain_text(warning.message)}")

        state.emit("policy-test", result, render=render)
        return EXIT_SUCCESS if result.accepted else EXIT_POLICY

    run(state, inner())
