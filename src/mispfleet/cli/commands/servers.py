"""Server commands: listing, health, versions, capabilities and templates."""

from __future__ import annotations

from typing import Annotated, Any

import typer
from rich.console import Console

from mispfleet.cli.context import (
    EXIT_AUTHENTICATION,
    EXIT_CONNECTIVITY,
    EXIT_PARTIAL,
    EXIT_SUCCESS,
    CLIState,
    guard,
    run,
    state_of,
)
from mispfleet.fleet import MispFleet, ServerSelector
from mispfleet.output.renderers import render_health, render_servers
from mispfleet.output.serializers import jsonable
from mispfleet.redaction import redact_mapping

app = typer.Typer(help="Inspect and probe configured servers.")
templates_app = typer.Typer(help="Object template operations.")
app.add_typer(templates_app, name="templates")


@app.command("list")
def list_servers(ctx: typer.Context) -> None:
    """List configured servers."""
    state = state_of(ctx)
    config = state.load_config()
    servers = list(config.servers.values())
    state.emit(
        "servers-list",
        {
            "servers": [
                redact_mapping(jsonable(server.model_dump(mode="json"))) for server in servers
            ]
        },
        render=lambda console: render_servers(console, servers),
    )


@app.command()
def show(ctx: typer.Context, name: Annotated[str, typer.Argument()]) -> None:
    """Show one server's configuration with credentials redacted."""
    state = state_of(ctx)

    def inner() -> None:
        config = state.load_config()
        fleet = MispFleet.from_config(config, interactive=False)
        server = fleet.registry.get(name)
        payload = redact_mapping(jsonable(server.model_dump(mode="json")))
        state.emit(
            "servers-show",
            {"server": payload},
            render=lambda console: console.print_json(data=payload),
        )

    guard(state, inner)


async def _health(state: CLIState, selector: ServerSelector | None) -> int:
    async with state.build_fleet() as fleet:
        result = await fleet.health(selector)
    state.emit(
        "fleet-health",
        result,
        render=lambda console: render_health(console, result),
    )
    return EXIT_PARTIAL if result.partial else EXIT_SUCCESS


@app.command()
def health(ctx: typer.Context) -> None:
    """Check health across the selected servers."""
    state = state_of(ctx)
    run(state, _health(state, state.selector()))


@app.command()
def test(ctx: typer.Context, name: Annotated[str, typer.Argument()]) -> None:
    """Probe a single server and exit non-zero on failure."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            result = await fleet.health(ServerSelector.names(name))
        health_result = result.results[name]
        state.emit(
            "server-test",
            health_result,
            render=lambda console: render_health(console, result),
        )
        if not health_result.reachable:
            return EXIT_CONNECTIVITY
        if not health_result.authenticated:
            return EXIT_AUTHENTICATION
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def versions(ctx: typer.Context) -> None:
    """Show MISP versions across the selected servers."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            result = await fleet.health(state.selector())
        rows = {
            name: (result.results[name].misp_version if name in result.results else None)
            for name in result.requested_servers
        }

        def render(console: Console) -> None:
            for name, version in rows.items():
                console.print(f"{name}: {version or 'unavailable'}")

        state.emit("servers-versions", {"versions": rows}, render=render)
        return EXIT_PARTIAL if result.partial else EXIT_SUCCESS

    run(state, inner())


@app.command()
def capabilities(ctx: typer.Context) -> None:
    """Show discovered capabilities across the selected servers."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            result = await fleet.health(state.selector())
        rows = {
            name: sorted(result.results[name].capabilities) if name in result.results else []
            for name in result.requested_servers
        }

        def render(console: Console) -> None:
            for name, items in rows.items():
                console.print(f"{name}: {','.join(items) or 'unavailable'}")

        state.emit("servers-capabilities", {"capabilities": rows}, render=render)
        return EXIT_PARTIAL if result.partial else EXIT_SUCCESS

    run(state, inner())


def _template_names(raw: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                template = item.get("ObjectTemplate", item)
                if isinstance(template, dict) and "name" in template:
                    names.add(str(template["name"]))
    return names


@templates_app.command("diff")
def templates_diff(
    ctx: typer.Context,
    left: Annotated[str, typer.Option("--left", help="Left server name.")],
    right: Annotated[str, typer.Option("--right", help="Right server name.")],
) -> None:
    """Compare available object templates between two servers."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            left_templates = _template_names(await fleet.client(left).templates.list())
            right_templates = _template_names(await fleet.client(right).templates.list())
        only_left = sorted(left_templates - right_templates)
        only_right = sorted(right_templates - left_templates)

        def render(console: Console) -> None:
            for name in only_left:
                console.print(f"only on {left}: {name}")
            for name in only_right:
                console.print(f"only on {right}: {name}")
            if not only_left and not only_right:
                console.print("object templates are identical")

        state.emit(
            "templates-diff",
            {"only_left": only_left, "only_right": only_right, "left": left, "right": right},
            render=render,
        )
        return EXIT_SUCCESS

    run(state, inner())
