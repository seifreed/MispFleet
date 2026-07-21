"""Unit tests for CLI shared state, exit codes and output emission."""

from __future__ import annotations

import io
import json
import logging
import sys
from datetime import timedelta
from pathlib import Path

import pytest
import typer
from rich.console import Console

from mispfleet.cli.app import main
from mispfleet.cli.commands.plugins import render_plugins
from mispfleet.cli.context import (
    EXIT_CANCELLED,
    CLIState,
    exit_code_for,
    guard,
    parse_duration,
    run,
    since_to_datetime,
)
from mispfleet.exceptions import (
    APIError,
    AuthenticationError,
    CapabilityError,
    ConflictError,
    InvalidConfigurationError,
    MispFleetError,
    MispServerError,
    NotFoundError,
    PartialFleetError,
    PolicyConfigurationError,
    PolicyViolationError,
    RequestTimeoutError,
    StalePlanError,
    StateError,
    TLSVerificationError,
    UnsafePlanError,
)
from mispfleet.logging import LOGGER_NAME
from tests.support import contains, eq, ok

CONFIG_TEXT = """
version: 1
servers:
  alpha:
    url: https://alpha.example
    credential: {provider: env, key: ALPHA}
"""


def state_with(**overrides: object) -> CLIState:
    state = CLIState()
    for key, value in overrides.items():
        setattr(state, key, value)
    return state


def test_parse_duration_units_and_errors() -> None:
    eq(parse_duration("30d"), timedelta(days=30))
    eq(parse_duration("12h"), timedelta(hours=12))
    eq(parse_duration("45m"), timedelta(minutes=45))
    eq(parse_duration("10s"), timedelta(seconds=10))
    eq(parse_duration("2w"), timedelta(weeks=2))
    with pytest.raises(typer.BadParameter):
        parse_duration("soon")
    ok(since_to_datetime("1h").tzinfo is not None)


def test_exit_code_for_covers_every_error_family() -> None:
    cases: list[tuple[MispFleetError, int]] = [
        (TLSVerificationError("tls"), 13),
        (AuthenticationError("auth"), 4),
        (InvalidConfigurationError("config"), 3),
        (PolicyConfigurationError("policy config"), 3),
        (ConflictError("conflict"), 9),
        (PolicyViolationError("policy"), 7),
        (StalePlanError("stale"), 8),
        (UnsafePlanError("unsafe"), 8),
        (CapabilityError("capability"), 10),
        (RequestTimeoutError("timeout"), 5),
        (PartialFleetError("partial", failed_servers=["x"]), 6),
        (NotFoundError("missing"), 1),
        (MispServerError("boom"), 1),
        (APIError("api"), 1),
        (StateError("state"), 1),
    ]
    for error, expected in cases:
        eq(exit_code_for(error), expected)


def test_configure_logging_levels() -> None:
    state_with(verbose=True).configure_logging()
    eq(logging.getLogger(LOGGER_NAME).level, logging.DEBUG)
    state_with(quiet=True).configure_logging()
    eq(logging.getLogger(LOGGER_NAME).level, logging.ERROR)
    state_with(log_format="json").configure_logging()
    logging.getLogger(LOGGER_NAME).handlers.clear()


def test_load_config_applies_cli_overrides(tmp_path: Path) -> None:
    path = tmp_path / "config.yml"
    path.write_text(CONFIG_TEXT, encoding="utf-8")
    base = state_with(config_path=path)
    eq(base.load_config().servers["alpha"].request_timeout, 60.0)
    with_timeout = state_with(config_path=path, timeout=5.0)
    eq(with_timeout.load_config().servers["alpha"].request_timeout, 5.0)
    with_concurrency = state_with(config_path=path, concurrency=2)
    eq(with_concurrency.load_config().servers["alpha"].concurrency, 2)


def test_selector_building_and_explicit_requirement() -> None:
    eq(CLIState().selector(), None)
    with pytest.raises(typer.BadParameter):
        CLIState().selector(require_explicit=True)
    selector = state_with(servers=["a"], groups=["g"], roles=["research"]).selector()
    ok(selector is not None)
    if selector is not None:
        eq(selector.server_names, {"a"})
        eq(selector.groups, {"g"})


def test_emit_formats_and_file_output(tmp_path: Path) -> None:
    rendered: list[str] = []
    state_with(output_format="table").emit(
        "op", {"x": 1}, render=lambda console: rendered.append("done")
    )
    eq(rendered, ["done"])
    capture = io.StringIO()
    stdout = sys.stdout
    sys.stdout = capture
    try:
        state_with(output_format="json").emit("op", {"x": 1})
        state_with(output_format="table").emit("op", {"x": 1})
        state_with(output_format="yaml").emit("op", {"x": 1})
        state_with(output_format="jsonl").emit("op", {"x": 1}, jsonl_records=[{"n": 1}])
    finally:
        sys.stdout = stdout
    output = capture.getvalue()
    contains(output, '"operation": "op"')
    contains(output, "operation: op")
    contains(output, '{"n": 1}')
    target = tmp_path / "out.json"
    state_with(output_format="json", output_path=target).emit("op", {"x": 1})
    eq(json.loads(target.read_text(encoding="utf-8"))["x"], 1)


def test_run_translates_errors_and_exit_codes() -> None:
    async def success() -> int:
        return 0

    run(CLIState(), success())

    async def nonzero() -> int:
        return 11

    with pytest.raises(typer.Exit) as exit_info:
        run(CLIState(), nonzero())
    eq(exit_info.value.exit_code, 11)

    async def failing() -> int:
        raise AuthenticationError("bad key")

    with pytest.raises(typer.Exit) as failed:
        run(CLIState(), failing())
    eq(failed.value.exit_code, 4)

    async def failing_traced() -> int:
        raise AuthenticationError("bad key")

    with pytest.raises(AuthenticationError):
        run(state_with(trace=True), failing_traced())

    async def cancelled() -> int:
        raise KeyboardInterrupt

    with pytest.raises(typer.Exit) as interrupted:
        run(CLIState(), cancelled())
    eq(interrupted.value.exit_code, EXIT_CANCELLED)


def test_guard_translates_errors() -> None:
    guard(CLIState(), lambda: None)
    with pytest.raises(typer.Exit) as failed:
        guard(CLIState(), _raise_config_error)
    eq(failed.value.exit_code, 3)
    with pytest.raises(InvalidConfigurationError):
        guard(state_with(trace=True), _raise_config_error)


def _raise_config_error() -> None:
    raise InvalidConfigurationError("nope")


def test_render_plugins_lists_entries() -> None:
    stream = io.StringIO()
    console = Console(file=stream, no_color=True)
    render_plugins(console, {"sample": "pkg.module:Plugin"})
    contains(stream.getvalue(), "sample: pkg.module:Plugin")


def test_main_entry_point_runs_the_app() -> None:
    argv = sys.argv
    sys.argv = ["mispfleet", "--version"]
    try:
        with pytest.raises(SystemExit) as exit_info:
            main()
        eq(exit_info.value.code, 0)
    finally:
        sys.argv = argv


def test_template_names_tolerates_malformed_payloads() -> None:
    from mispfleet.cli.commands.servers import _template_names

    eq(_template_names({"not": "a list"}), set())
    eq(
        _template_names(
            [{"ObjectTemplate": {"name": "file"}}, {"name": "network"}, {"noname": 1}, "junk"]
        ),
        {"file", "network"},
    )
