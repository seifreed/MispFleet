"""Fleet-wide sighting propagation commands."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console

from mispfleet.cli.context import (
    EXIT_NO_MATCHES,
    EXIT_PARTIAL,
    EXIT_SUCCESS,
    run,
    state_of,
)
from mispfleet.output.renderers import plain_text

app = typer.Typer(help="Record sightings across the fleet.")


@app.command()
def push(
    ctx: typer.Context,
    indicator: Annotated[str, typer.Argument(help="Indicator value that was sighted.")],
    source: Annotated[str, typer.Option(help="Sighting source label.")] = "",
    sighting_type: Annotated[
        str, typer.Option("--type", help="Sighting type: 0 sighting, 1 false positive.")
    ] = "0",
) -> None:
    """Record a sighting of an indicator on every selected server."""
    state = state_of(ctx)
    selector = state.selector(require_explicit=True)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            result = await fleet.add_sighting(
                indicator, selector=selector, source=source, sighting_type=sighting_type
            )
        total = sum(result.results.values())

        def render(console: Console) -> None:
            for name, count in result.results.items():
                console.print(f"{plain_text(name)}: {count} sighting(s) recorded")
            for name, error in result.errors.items():
                console.print(f"[red]failed[/red] {plain_text(name)}: {plain_text(error.message)}")

        state.emit("fleet-sighting-push", result, render=render, partial=result.partial)
        if result.partial:
            return EXIT_PARTIAL
        if total == 0:
            return EXIT_NO_MATCHES
        return EXIT_SUCCESS

    run(state, inner())
