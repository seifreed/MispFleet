"""Apply a previously generated operation plan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError as PydanticValidationError

from mispfleet.cli.context import EXIT_SUCCESS, EXIT_USAGE, run, state_of
from mispfleet.models.plan import CopyPlan
from mispfleet.output.renderers import render_apply_result
from mispfleet.settings import default_state_path
from mispfleet.state.sqlite import SqliteStateBackend


def apply_plan(
    ctx: typer.Context,
    plan_file: Annotated[Path, typer.Argument(help="Path to a plan JSON file.")],
) -> None:
    """Re-validate and apply a plan file."""
    state = state_of(ctx)
    try:
        raw = json.loads(plan_file.read_text(encoding="utf-8"))
        plan = CopyPlan.model_validate(raw)
    except (OSError, ValueError, PydanticValidationError) as error:
        typer.echo(f"invalid plan file: {error}", err=True)
        raise typer.Exit(EXIT_USAGE) from error

    async def inner() -> int:
        backend = SqliteStateBackend(default_state_path())
        await backend.initialize()
        try:
            async with state.build_fleet(state_backend=backend) as fleet:
                result = await fleet.apply(plan)
        finally:
            await backend.close()
        state.emit(
            "copy-apply",
            result,
            render=lambda console: render_apply_result(console, result),
        )
        return EXIT_SUCCESS

    run(state, inner())
