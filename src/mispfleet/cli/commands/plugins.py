"""Plugin commands."""

from __future__ import annotations

from datetime import UTC, datetime

import typer
from rich.console import Console

from mispfleet.cli.context import EXIT_SUCCESS, run, state_of
from mispfleet.exceptions import ConfigurationError
from mispfleet.output.renderers import plain_text
from mispfleet.plugins.loader import discover_plugins
from mispfleet.state.base import PluginRecord, StateBackend

app = typer.Typer(help="Discover installed plugins.")


def render_plugins(console: Console, available: dict[str, str]) -> None:
    """Render the advertised plugin table."""
    if not available:
        console.print("no plugins installed")
    for name, target in sorted(available.items()):
        console.print(f"{plain_text(name)}: {plain_text(target)}")


async def record_plugins(backend: StateBackend, available: dict[str, str]) -> None:
    """Persist the metadata of every discovered plugin entry point."""
    discovered_at = datetime.now(tz=UTC)
    for name, target in sorted(available.items()):
        await backend.save_plugin(
            PluginRecord(name=name, target=target, discovered_at=discovered_at)
        )


@app.command("list")
def list_plugins(ctx: typer.Context) -> None:
    """List plugins advertised through the mispfleet.plugins entry point.

    Discovered entry points are recorded in the state backend when a
    configuration is available; plugins are never loaded or activated by
    listing them.
    """
    state = state_of(ctx)

    async def inner() -> int:
        available = discover_plugins()
        try:
            backend = state.state_backend()
        except ConfigurationError:
            backend = None
        if backend is not None:
            await backend.initialize()
            try:
                await record_plugins(backend, available)
            finally:
                await backend.close()
        state.emit(
            "plugins-list",
            {"plugins": available},
            render=lambda console: render_plugins(console, available),
        )
        return EXIT_SUCCESS

    run(state, inner())
