"""CLI entry point: global options and command registration."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from typer._click.core import Context as ClickContext
from typer.core import TyperGroup

from mispfleet._version import __version__
from mispfleet.cli.commands import config as config_commands
from mispfleet.cli.commands import event as event_commands
from mispfleet.cli.commands import plugins as plugin_commands
from mispfleet.cli.commands import policy as policy_commands
from mispfleet.cli.commands import search as search_commands
from mispfleet.cli.commands import servers as server_commands
from mispfleet.cli.commands import state as state_commands
from mispfleet.cli.commands.apply import apply_plan
from mispfleet.cli.context import CLIState

_GLOBAL_FLAGS = frozenset(
    {
        "--all",
        "--no-color",
        "--quiet",
        "--verbose",
        "--non-interactive",
        "--trace",
    }
)

_GLOBAL_VALUE_OPTIONS = frozenset(
    {
        "--config",
        "--profile",
        "--server",
        "--group",
        "--role",
        "--exclude-server",
        "--format",
        "--output",
        "--log-level",
        "--log-format",
        "--timeout",
        "--concurrency",
    }
)


class GlobalOptionsGroup(TyperGroup):
    """Accepts global options anywhere on the command line.

    The specified CLI allows ``mispfleet search value X --all --format json``;
    click normally requires group options before the subcommand, so known
    global options are hoisted to the front before parsing. ``--tag`` is not
    hoisted because some subcommands define their own ``--tag`` filter.
    """

    def parse_args(self, ctx: ClickContext, args: list[str]) -> list[str]:
        front: list[str] = []
        rest: list[str] = []
        index = 0
        while index < len(args):
            argument = args[index]
            key = argument.split("=", 1)[0]
            if argument in _GLOBAL_FLAGS or (key in _GLOBAL_VALUE_OPTIONS and "=" in argument):
                front.append(argument)
                index += 1
            elif argument in _GLOBAL_VALUE_OPTIONS and index + 1 < len(args):
                front.extend(args[index : index + 2])
                index += 2
            else:
                rest.append(argument)
                index += 1
        return super().parse_args(ctx, front + rest)


app = typer.Typer(
    name="mispfleet",
    help="Operate multiple MISP instances as a coordinated fleet.",
    no_args_is_help=True,
    cls=GlobalOptionsGroup,
)

app.add_typer(config_commands.app, name="config")
app.add_typer(server_commands.app, name="servers")
app.add_typer(search_commands.app, name="search")
app.add_typer(event_commands.app, name="event")
app.add_typer(policy_commands.app, name="policy")
app.add_typer(state_commands.app, name="state")
app.add_typer(plugin_commands.app, name="plugins")
app.command("apply")(apply_plan)


@app.command()
def version() -> None:
    """Print the mispfleet version."""
    typer.echo(__version__)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main_callback(
    ctx: typer.Context,
    config: Annotated[
        Path | None, typer.Option("--config", envvar="MISPFLEET_CONFIG", help="Config file path.")
    ] = None,
    profile: Annotated[
        str | None, typer.Option(envvar="MISPFLEET_PROFILE", help="Configuration profile.")
    ] = None,
    server: Annotated[list[str] | None, typer.Option("--server", help="Select by name.")] = None,
    group: Annotated[list[str] | None, typer.Option("--group", help="Select by group.")] = None,
    tag: Annotated[list[str] | None, typer.Option("--tag", help="Select by tag.")] = None,
    role: Annotated[list[str] | None, typer.Option("--role", help="Select by role.")] = None,
    select_all: Annotated[bool, typer.Option("--all", help="Select every enabled server.")] = False,
    exclude_server: Annotated[
        list[str] | None, typer.Option("--exclude-server", help="Exclude a server.")
    ] = None,
    output_format: Annotated[
        str,
        typer.Option("--format", envvar="MISPFLEET_OUTPUT", help="table, json, jsonl or yaml."),
    ] = "table",
    output: Annotated[Path | None, typer.Option(help="Write machine output to a file.")] = None,
    log_level: Annotated[
        str, typer.Option(envvar="MISPFLEET_LOG_LEVEL", help="debug, info, warning or error.")
    ] = "warning",
    log_format: Annotated[str, typer.Option(help="Log format: text or json.")] = "text",
    no_color: Annotated[
        bool, typer.Option("--no-color", envvar="MISPFLEET_NO_COLOR", help="Disable color.")
    ] = False,
    quiet: Annotated[bool, typer.Option("--quiet", help="Only errors on stderr.")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", help="Debug logging.")] = False,
    timeout: Annotated[
        float | None, typer.Option(help="Override per-request timeout (seconds).")
    ] = None,
    concurrency: Annotated[
        int | None, typer.Option(help="Override per-server concurrency.")
    ] = None,
    non_interactive: Annotated[
        bool, typer.Option("--non-interactive", help="Never prompt for input.")
    ] = False,
    trace: Annotated[bool, typer.Option("--trace", help="Raw tracebacks for debugging.")] = False,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Collect global options shared by every command."""
    if output_format not in ("table", "json", "jsonl", "yaml"):
        raise typer.BadParameter(f"unsupported format {output_format!r}")
    state = CLIState(
        config_path=config,
        profile=profile,
        servers=list(server or []),
        groups=list(group or []),
        tags=list(tag or []),
        roles=list(role or []),
        excluded=list(exclude_server or []),
        select_all=select_all,
        output_format=output_format,
        output_path=output,
        log_level=log_level,
        log_format=log_format,
        no_color=no_color,
        quiet=quiet,
        verbose=verbose,
        timeout=timeout,
        concurrency=concurrency,
        non_interactive=non_interactive,
        trace=trace,
    )
    state.configure_logging()
    ctx.obj = state


def main() -> None:
    """Console-script entry point."""
    app()
