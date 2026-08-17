"""Shared CLI state, exit-code mapping and output emission."""

from __future__ import annotations

import asyncio
import os
import re
import sys
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import typer
from rich.console import Console

from mispfleet.exceptions import (
    APIError,
    AttachmentSecurityError,
    AuthenticationError,
    CapabilityError,
    ConfigurationError,
    ConflictError,
    InvalidConfigurationError,
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
from mispfleet.output.renderers import plain_text
from mispfleet.output.serializers import document, serialize
from mispfleet.settings import ENV_ACTOR, FleetConfig, build_state_backend, load_fleet_config
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
    try:
        return timedelta(seconds=int(match.group("amount")) * _UNIT_SECONDS[match.group("unit")])
    except OverflowError as error:
        # The regex accepts any number of digits; timedelta does not.
        raise typer.BadParameter(f"duration {text!r} is out of range") from error


def since_to_datetime(text: str) -> datetime:
    """Convert a relative duration into an absolute UTC instant."""
    try:
        return datetime.now(tz=UTC) - parse_duration(text)
    except OverflowError as error:
        raise typer.BadParameter(f"duration {text!r} is out of range") from error


def exit_code_for(error: MispFleetError) -> int:
    """Map a typed exception onto the documented CLI exit codes."""
    if isinstance(error, TLSVerificationError | AttachmentSecurityError):
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


class _PipeTolerantConsole(Console):
    """Console that treats a reader closing the pipe as success.

    rich's default ``on_broken_pipe`` exits 1, so ``mispfleet servers list |
    head`` reported a failure for exactly the condition the machine formats
    report as 0.
    """

    def on_broken_pipe(self) -> None:
        """Absorb the closed pipe and exit as the machine formats do."""
        self.quiet = True
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(EXIT_SUCCESS)


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
    no_verify_tls: bool = False

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
        return _PipeTolerantConsole(no_color=self.no_color, highlight=False)

    def single_server(self) -> str:
        """The one selected server, or a usage error when the selection is not unique."""
        if len(self.servers) == 1:
            return self.servers[0]
        raise typer.BadParameter("specify exactly one server with --server NAME")

    def load_config(self) -> FleetConfig:
        """Load configuration applying CLI-level overrides."""
        config = load_fleet_config(self.config_path, self.profile)
        if self.no_verify_tls and config.security.forbid_insecure_tls:
            raise InvalidConfigurationError(
                "--no-verify-tls is not allowed: the configuration forbids "
                "insecure TLS (security.forbid_insecure_tls)"
            )
        if self.timeout is not None or self.concurrency is not None or self.no_verify_tls:
            overrides: dict[str, Any] = {}
            if self.timeout is not None:
                overrides["request_timeout"] = self.timeout
            if self.concurrency is not None:
                overrides["concurrency"] = self.concurrency
            if self.no_verify_tls:
                overrides["verify_tls"] = False
            config = config.model_copy(
                update={
                    "servers": {
                        name: server.model_copy(update=overrides)
                        for name, server in config.servers.items()
                    }
                }
            )
        return config

    def state_backend(self) -> StateBackend:
        """Instantiate the configured state backend (not yet initialized)."""
        return build_state_backend(self.load_config().state)

    def build_fleet(self, state_backend: StateBackend | None = None) -> MispFleet:
        """Build the fleet from configuration; interactive prompts obey flags."""
        return MispFleet.from_config(
            self.load_config(),
            interactive=not self.non_interactive,
            state=state_backend,
            actor=os.environ.get(ENV_ACTOR) or None,
        )

    @asynccontextmanager
    async def open_backend(self) -> AsyncIterator[StateBackend]:
        """An initialized state backend, closed when the block exits."""
        backend = self.state_backend()
        await backend.initialize()
        try:
            yield backend
        finally:
            await backend.close()

    @asynccontextmanager
    async def fleet_session(self) -> AsyncIterator[MispFleet]:
        """A fleet wired to an initialized state backend; both released on exit."""
        async with self.open_backend() as backend, self.build_fleet(state_backend=backend) as fleet:
            yield fleet

    def selector(self, require_explicit: bool = False) -> ServerSelector | None:
        """Build the server selector from CLI options."""
        try:
            roles = {ServerRole(role) for role in self.roles}
        except ValueError as error:
            known = ", ".join(sorted(role.value for role in ServerRole))
            raise typer.BadParameter(f"unknown --role; expected one of: {known}") from error
        selector = ServerSelector(
            server_names=set(self.servers),
            groups=set(self.groups),
            tags=set(self.tags),
            roles=roles,
            excluded=set(self.excluded),
            select_all=self.select_all,
        )
        if not selector.is_explicit:
            if require_explicit:
                raise typer.BadParameter(
                    "this operation requires an explicit selector: "
                    "--server, --group, --tag, --role or --all"
                )
            if selector.excluded:
                # Exclusions alone read as "every server but these": returning
                # None here fell back to ServerSelector.all() with an empty
                # excluded set, so --exclude-server on its own was a silent
                # no-op and the excluded server was contacted anyway.
                return selector.model_copy(update={"select_all": True})
            return None
        return selector

    def discard_closed_stdout(self) -> None:
        """Absorb a reader that closed the pipe, e.g. `mispfleet ... | head`.

        Nothing failed, so the exit code stays 0 for every output format;
        pointing stdout at the null device keeps the interpreter's shutdown
        flush from reporting the same broken pipe again on stderr.
        """
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise typer.Exit(EXIT_SUCCESS)

    def emit(
        self,
        operation: str,
        payload: Any,
        render: Callable[[Console], None] | None = None,
        jsonl_records: list[Any] | None = None,
        patch_text: Callable[[], str] | None = None,
        **extra: Any,
    ) -> None:
        """Emit machine output to stdout/file, or human output to the console."""
        if self.output_format == "table" and render is not None:
            render(self.console())
            return
        if self.output_format == "patch":
            if patch_text is None:
                raise typer.BadParameter("--format patch is only supported by 'event diff'")
            text = patch_text()
        elif self.output_format == "jsonl":
            # Commands without per-record output still owe the caller valid
            # JSONL: one object per line, never an indented JSON document.
            records = (
                jsonl_records
                if jsonl_records is not None
                else [document(operation, payload, **extra)]
            )
            text = serialize(records, "jsonl")
        elif self.output_format == "yaml":
            text = serialize(document(operation, payload, **extra), "yaml")
        else:
            text = serialize(document(operation, payload, **extra), "json")
        if self.output_path is not None:
            write_output_file(self.output_path, text)
            return
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except BrokenPipeError:
            self.discard_closed_stdout()


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
        Console(stderr=True, no_color=state.no_color).print(
            f"[red]error[/red]: {plain_text(error.message)}"
        )
        raise typer.Exit(exit_code_for(error)) from error
    except KeyboardInterrupt:
        raise typer.Exit(EXIT_CANCELLED) from None


def write_output_file(path: Path, text: str) -> None:
    """Write ``text`` to a CLI output path, typing an unwritable target.

    An unwritable ``--output``/``--plan-output`` (missing directory, no
    permission) is operator error, so it must surface as the one-line usage
    error every other write path already reports, not as a raw OSError
    traceback with exit 1.
    """
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as error:
        raise typer.BadParameter(f"cannot write {path}: {error}") from error


def run(state: CLIState, coroutine: Coroutine[Any, Any, int]) -> None:
    """Run an async command, translating typed errors into exit codes."""
    try:
        code = asyncio.run(coroutine)
    except MispFleetError as error:
        if state.trace:
            raise
        Console(stderr=True, no_color=state.no_color).print(
            f"[red]error[/red]: {plain_text(error.message)}"
        )
        raise typer.Exit(exit_code_for(error)) from error
    except KeyboardInterrupt:
        raise typer.Exit(EXIT_CANCELLED) from None
    if code != EXIT_SUCCESS:
        raise typer.Exit(code)


OutputFormatOption = Literal["table", "json", "jsonl", "yaml", "patch"]
