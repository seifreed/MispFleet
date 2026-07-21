"""Shared CLI state, exit-code mapping and output emission."""

from __future__ import annotations

import asyncio
import re
import sys
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import typer
from rich.console import Console

from mispfleet.exceptions import (
    APIError,
    AuthenticationError,
    CapabilityError,
    ConfigurationError,
    ConflictError,
    MispFleetError,
    PartialFleetError,
    PlanError,
    PolicyConfigurationError,
    PolicyError,
    TLSVerificationError,
    TransportError,
)
from mispfleet.fleet import MispFleet, ServerSelector
from mispfleet.logging import configure_cli_logging
from mispfleet.models.common import ServerRole
from mispfleet.output.serializers import document, serialize
from mispfleet.settings import FleetConfig, load_fleet_config
from mispfleet.state.base import StateBackend

EXIT_SUCCESS = 0
EXIT_GENERIC = 1
EXIT_USAGE = 2
EXIT_CONFIGURATION = 3
EXIT_AUTHENTICATION = 4
EXIT_CONNECTIVITY = 5
EXIT_PARTIAL = 6
EXIT_POLICY = 7
EXIT_PLAN = 8
EXIT_CONFLICT = 9
EXIT_CAPABILITY = 10
EXIT_NO_MATCHES = 11
EXIT_CANCELLED = 12
EXIT_SECURITY = 13

_DURATION = re.compile(r"^(?P<amount>\d+)(?P<unit>[smhdw])$")

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> timedelta:
    """Parse durations like ``30d``, ``12h``, ``45m``."""
    match = _DURATION.match(text.strip())
    if match is None:
        raise typer.BadParameter(f"invalid duration {text!r}; use forms like 30d, 12h, 45m")
    return timedelta(seconds=int(match.group("amount")) * _UNIT_SECONDS[match.group("unit")])


def since_to_datetime(text: str) -> datetime:
    """Convert a relative duration into an absolute UTC instant."""
    return datetime.now(tz=UTC) - parse_duration(text)


def exit_code_for(error: MispFleetError) -> int:
    """Map a typed exception onto the documented CLI exit codes."""
    if isinstance(error, TLSVerificationError):
        return EXIT_SECURITY
    if isinstance(error, AuthenticationError):
        return EXIT_AUTHENTICATION
    if isinstance(error, PolicyConfigurationError | ConfigurationError):
        return EXIT_CONFIGURATION
    if isinstance(error, ConflictError):
        return EXIT_CONFLICT
    if isinstance(error, PolicyError):
        return EXIT_POLICY
    if isinstance(error, PlanError):
        return EXIT_PLAN
    if isinstance(error, CapabilityError):
        return EXIT_CAPABILITY
    if isinstance(error, TransportError):
        return EXIT_CONNECTIVITY
    if isinstance(error, PartialFleetError):
        return EXIT_PARTIAL
    if isinstance(error, APIError):
        return EXIT_GENERIC
    return EXIT_GENERIC


@dataclass
class CLIState:
    """Global options collected by the root command."""

    config_path: Path | None = None
    profile: str | None = None
    servers: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    select_all: bool = False
    output_format: str = "table"
    output_path: Path | None = None
    log_level: str = "warning"
    log_format: str = "text"
    no_color: bool = False
    quiet: bool = False
    verbose: bool = False
    timeout: float | None = None
    concurrency: int | None = None
    non_interactive: bool = False
    trace: bool = False

    def configure_logging(self) -> None:
        """Attach the redacting stderr handler to the mispfleet hierarchy."""
        level = "debug" if self.verbose or self.trace else self.log_level
        if self.quiet:
            level = "error"
        configure_cli_logging(
            level=level,
            log_format="json" if self.log_format == "json" else "text",
        )

    def console(self) -> Console:
        """Human output console (stdout)."""
        return Console(no_color=self.no_color, highlight=False)

    def load_config(self) -> FleetConfig:
        """Load configuration applying CLI-level overrides."""
        config = load_fleet_config(self.config_path, self.profile)
        if self.timeout is not None or self.concurrency is not None:
            overrides: dict[str, Any] = {}
            if self.timeout is not None:
                overrides["request_timeout"] = self.timeout
            if self.concurrency is not None:
                overrides["concurrency"] = self.concurrency
            config = config.model_copy(
                update={
                    "servers": {
                        name: server.model_copy(update=overrides)
                        for name, server in config.servers.items()
                    }
                }
            )
        return config

    def build_fleet(self, state_backend: StateBackend | None = None) -> MispFleet:
        """Build the fleet from configuration; interactive prompts obey flags."""
        return MispFleet.from_config(
            self.load_config(),
            interactive=not self.non_interactive,
            state=state_backend,
        )

    def selector(self, require_explicit: bool = False) -> ServerSelector | None:
        """Build the server selector from CLI options."""
        selector = ServerSelector(
            server_names=set(self.servers),
            groups=set(self.groups),
            tags=set(self.tags),
            roles={ServerRole(role) for role in self.roles},
            excluded=set(self.excluded),
            select_all=self.select_all,
        )
        if not selector.is_explicit:
            if require_explicit:
                raise typer.BadParameter(
                    "this operation requires an explicit selector: "
                    "--server, --group, --tag, --role or --all"
                )
            return None
        return selector

    def emit(
        self,
        operation: str,
        payload: Any,
        render: Callable[[Console], None] | None = None,
        jsonl_records: list[Any] | None = None,
        **extra: Any,
    ) -> None:
        """Emit machine output to stdout/file, or human output to the console."""
        if self.output_format == "table" and render is not None:
            render(self.console())
            return
        if self.output_format == "jsonl" and jsonl_records is not None:
            text = serialize(jsonl_records, "jsonl")
        elif self.output_format == "yaml":
            text = serialize(document(operation, payload, **extra), "yaml")
        else:
            text = serialize(document(operation, payload, **extra), "json")
        if self.output_path is not None:
            self.output_path.write_text(text, encoding="utf-8")
            return
        sys.stdout.write(text)


def state_of(ctx: typer.Context) -> CLIState:
    """Fetch the shared state stored by the root callback."""
    return cast(CLIState, ctx.obj)


def guard(state: CLIState, fn: Callable[[], None]) -> None:
    """Run a synchronous command body, translating typed errors to exit codes."""
    try:
        fn()
    except MispFleetError as error:
        if state.trace:
            raise
        Console(stderr=True, no_color=state.no_color).print(f"[red]error[/red]: {error.message}")
        raise typer.Exit(exit_code_for(error)) from error


def run(state: CLIState, coroutine: Coroutine[Any, Any, int]) -> None:
    """Run an async command, translating typed errors into exit codes."""
    try:
        code = asyncio.run(coroutine)
    except MispFleetError as error:
        if state.trace:
            raise
        Console(stderr=True, no_color=state.no_color).print(f"[red]error[/red]: {error.message}")
        raise typer.Exit(exit_code_for(error)) from error
    except KeyboardInterrupt:
        raise typer.Exit(EXIT_CANCELLED) from None
    if code != EXIT_SUCCESS:
        raise typer.Exit(code)


OutputFormatOption = Literal["table", "json", "jsonl", "yaml"]
