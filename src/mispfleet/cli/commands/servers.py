"""Server commands: listing, health, versions, capabilities and templates."""

from __future__ import annotations

from typing import Annotated, Any

import typer
from rich.console import Console

from mispfleet.cli.context import (
    EXIT_AUTHENTICATION,
    EXIT_CONFLICT,
    EXIT_CONNECTIVITY,
    EXIT_PARTIAL,
    EXIT_SUCCESS,
    CLIState,
    guard,
    run,
    state_of,
)
from mispfleet.exceptions import MispFleetError
from mispfleet.fleet import MispFleet, ServerSelector
from mispfleet.output.renderers import plain_text, render_audit, render_health, render_servers
from mispfleet.output.serializers import jsonable
from mispfleet.redaction import redact_mapping
from mispfleet.state.base import CapabilityRecord

app = typer.Typer(help="Inspect and probe configured servers.")
templates_app = typer.Typer(help="Object template operations.")
app.add_typer(templates_app, name="templates")


@app.command("list")
def list_servers(ctx: typer.Context) -> None:
    """List configured servers."""
    state = state_of(ctx)

    def body() -> None:
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

    guard(state, body)


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
    degraded = result.partial or any(health.error is not None for health in result.results.values())
    return EXIT_PARTIAL if degraded else EXIT_SUCCESS


@app.command()
def health(ctx: typer.Context) -> None:
    """Check health across the selected servers."""
    state = state_of(ctx)
    run(state, _health(state, state.selector()))


@app.command()
def audit(ctx: typer.Context) -> None:
    """Audit configuration consistency (taxonomies, warninglists, galaxies, feeds, templates)."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            result = await fleet.audit(state.selector())
        state.emit(
            "fleet-audit",
            result,
            render=lambda console: render_audit(console, result),
        )
        if result.partial:
            return EXIT_PARTIAL
        return EXIT_SUCCESS if result.consistent else EXIT_CONFLICT

    run(state, inner())


def _render_server_messages(rows: dict[str, Any], failed: dict[str, str]) -> Any:
    def render(console: Console) -> None:
        for name, message in rows.items():
            console.print(f"{plain_text(name)}: {plain_text(message)}")
        for name, message in failed.items():
            console.print(f"[red]failed[/red] {plain_text(name)}: {plain_text(message)}")

    return render


@app.command("update-libraries")
def update_libraries(ctx: typer.Context) -> None:
    """Refresh taxonomy, warninglist, galaxy and noticelist libraries fleet-wide."""
    state = state_of(ctx)
    selector = state.selector(require_explicit=True)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            result = await fleet.update_libraries(selector)
        rows = {
            name: ", ".join(f"{library} {message}" for library, message in sorted(items.items()))
            for name, items in result.results.items()
        }
        failed = {name: error.message for name, error in result.errors.items()}
        state.emit(
            "fleet-update-libraries",
            result,
            render=_render_server_messages(rows, failed),
        )
        return EXIT_PARTIAL if result.partial else EXIT_SUCCESS

    run(state, inner())


async def _toggle_library(
    state: CLIState,
    kind: str,
    name: str,
    enabled: bool,
) -> int:
    selector = state.selector(require_explicit=True)
    async with state.build_fleet() as fleet:
        if kind == "warninglist":
            result = await fleet.set_warninglist(name, enabled, selector)
        else:
            result = await fleet.set_taxonomy(name, enabled, selector)
    failed = {server: error.message for server, error in result.errors.items()}
    state.emit(
        f"fleet-{kind}-toggle",
        result,
        render=_render_server_messages(dict(result.results), failed),
    )
    return EXIT_PARTIAL if result.partial else EXIT_SUCCESS


DisableOption = Annotated[bool, typer.Option("--disable", help="Disable instead of enable.")]


@app.command("enable-warninglist")
def enable_warninglist(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Warninglist name.")],
    disable: DisableOption = False,
) -> None:
    """Enable (or disable) one warninglist by name across the selected servers."""
    state = state_of(ctx)
    run(state, _toggle_library(state, "warninglist", name, not disable))


@app.command("enable-taxonomy")
def enable_taxonomy(
    ctx: typer.Context,
    namespace: Annotated[str, typer.Argument(help="Taxonomy namespace, e.g. tlp.")],
    disable: DisableOption = False,
) -> None:
    """Enable (or disable) one taxonomy by namespace across the selected servers."""
    state = state_of(ctx)
    run(state, _toggle_library(state, "taxonomy", namespace, not disable))


@app.command()
def test(ctx: typer.Context, name: Annotated[str, typer.Argument()]) -> None:
    """Probe a single server and exit non-zero on failure."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            result = await fleet.health(ServerSelector.names(name))
        health_result = result.results.get(name)
        if health_result is None:
            # A failure before the probe itself — a credential that cannot be
            # resolved, most often — is recorded as a server error, never as a
            # health result; indexing it raised KeyError as a raw traceback.
            failure = result.errors[name]
            state.emit(
                "server-test",
                failure,
                render=lambda console: console.print(
                    f"[red]failed[/red] {plain_text(name)}: {plain_text(failure.message)}"
                ),
            )
            return EXIT_CONNECTIVITY
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


async def _capability_records(
    state: CLIState, refresh: bool
) -> tuple[dict[str, CapabilityRecord | None], bool]:
    """Fetch (or read from cache) capability records for the selected servers."""
    ttl = state.load_config().state.capability_ttl_seconds
    records: dict[str, CapabilityRecord | None] = {}
    partial = False
    async with state.fleet_session() as fleet:
        for name in fleet.select(state.selector()):
            try:
                records[name] = await fleet.server_capabilities(
                    name, refresh=refresh, ttl_seconds=ttl
                )
            except MispFleetError:
                records[name] = None
                partial = True
    return records, partial


RefreshOption = Annotated[
    bool, typer.Option("--refresh", help="Ignore the cache and probe the servers.")
]


@app.command()
def versions(ctx: typer.Context, refresh: RefreshOption = False) -> None:
    """Show MISP versions across the selected servers."""
    state = state_of(ctx)

    async def inner() -> int:
        records, partial = await _capability_records(state, refresh)
        rows = {
            name: record.misp_version if record is not None else None
            for name, record in records.items()
        }

        def render(console: Console) -> None:
            for name, version in rows.items():
                console.print(f"{plain_text(name)}: {plain_text(version or 'unavailable')}")

        state.emit("servers-versions", {"versions": rows}, render=render)
        return EXIT_PARTIAL if partial else EXIT_SUCCESS

    run(state, inner())


@app.command()
def capabilities(ctx: typer.Context, refresh: RefreshOption = False) -> None:
    """Show discovered capabilities across the selected servers."""
    state = state_of(ctx)

    async def inner() -> int:
        records, partial = await _capability_records(state, refresh)
        rows = {
            name: sorted(record.capabilities) if record is not None else []
            for name, record in records.items()
        }

        def render(console: Console) -> None:
            for name, items in rows.items():
                console.print(f"{plain_text(name)}: {plain_text(','.join(items) or 'unavailable')}")

        state.emit("servers-capabilities", {"capabilities": rows}, render=render)
        return EXIT_PARTIAL if partial else EXIT_SUCCESS

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
                console.print(f"only on {plain_text(left)}: {plain_text(name)}")
            for name in only_right:
                console.print(f"only on {plain_text(right)}: {plain_text(name)}")
            if not only_left and not only_right:
                console.print("object templates are identical")

        state.emit(
            "templates-diff",
            {"only_left": only_left, "only_right": only_right, "left": left, "right": right},
            render=render,
        )
        return EXIT_SUCCESS

    run(state, inner())
