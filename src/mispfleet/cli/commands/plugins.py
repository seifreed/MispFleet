"""Plugin commands."""

from __future__ import annotations

import typer
from rich.console import Console

from mispfleet.cli.context import state_of
from mispfleet.plugins.loader import discover_plugins

app = typer.Typer(help="Discover installed plugins.")


def render_plugins(console: Console, available: dict[str, str]) -> None:
    """Render the advertised plugin table."""
    if not available:
        console.print("no plugins installed")
    for name, target in sorted(available.items()):
        console.print(f"{name}: {target}")


@app.command("list")
def list_plugins(ctx: typer.Context) -> None:
    """List plugins advertised through the mispfleet.plugins entry point."""
    state = state_of(ctx)
    available = discover_plugins()
    state.emit(
        "plugins-list",
        {"plugins": available},
        render=lambda console: render_plugins(console, available),
    )
