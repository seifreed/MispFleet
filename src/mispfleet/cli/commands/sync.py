"""Synchronization job commands."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from mispfleet.cli.context import EXIT_PARTIAL, EXIT_PLAN, EXIT_SUCCESS, run, state_of
from mispfleet.models.sync import SyncPlan, SyncResult
from mispfleet.output.serializers import document, serialize

app = typer.Typer(help="Plan and run declarative synchronization jobs.")


def render_sync_plan(console: Console, plan: SyncPlan) -> None:
    """Render a synchronization plan review."""
    console.print(
        f"Sync plan {plan.plan_id} for job {plan.job!r}: "
        f"{plan.left_server} <-> {plan.right_server}"
    )
    for copy in plan.copies_left_to_right:
        console.print(f"  {plan.left_server} -> {plan.right_server}: {copy.source_event_uuid}")
    for copy in plan.copies_right_to_left:
        console.print(f"  {plan.right_server} -> {plan.left_server}: {copy.source_event_uuid}")
    for conflict in plan.conflicts:
        console.print(f"  [yellow]conflict[/yellow] {conflict.event_uuid}: {conflict.resolution}")
    console.print(f"  in sync: {plan.in_sync}, copies proposed: {plan.total_copies}")
    if plan.blocked:
        console.print("  [red]plan contains blocking errors[/red]")


def render_sync_result(console: Console, result: SyncResult) -> None:
    """Render the outcome of applying a synchronization plan."""
    console.print(f"Sync {result.plan_id}: {len(result.applied)} change(s) applied")
    for event_uuid, message in sorted(result.failures.items()):
        console.print(f"  [red]failed[/red] {event_uuid}: {message}")


@app.command("list")
def list_jobs(ctx: typer.Context) -> None:
    """List configured synchronization jobs."""
    state = state_of(ctx)
    jobs = state.load_config().sync_jobs

    def render(console: Console) -> None:
        if not jobs:
            console.print("no sync jobs configured")
        for name, job in sorted(jobs.items()):
            console.print(
                f"{name}: {job.left} <-> {job.right} "
                f"direction={job.direction.value} on_conflict={job.on_conflict.value}"
            )

    state.emit(
        "sync-list",
        {"jobs": {name: job.model_dump(mode="json") for name, job in jobs.items()}},
        render=render,
    )


@app.command()
def plan(
    ctx: typer.Context,
    job: Annotated[str, typer.Argument(help="Configured sync job name.")],
    plan_output: Annotated[
        Path | None, typer.Option(help="Write the generated plan to this file.")
    ] = None,
) -> None:
    """Plan a synchronization job without mutating any server."""
    state = state_of(ctx)

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            sync_plan = await fleet.plan_sync(job)
        if plan_output is not None:
            plan_output.write_text(
                serialize(document("sync-plan", sync_plan), "json"), encoding="utf-8"
            )
        state.emit(
            "sync-plan",
            sync_plan,
            render=lambda console: render_sync_plan(console, sync_plan),
        )
        return EXIT_PLAN if sync_plan.blocked else EXIT_SUCCESS

    run(state, inner())


@app.command("run")
def run_job(
    ctx: typer.Context,
    job: Annotated[str, typer.Argument(help="Configured sync job name.")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Plan only, never mutate.")] = False,
) -> None:
    """Plan and apply a synchronization job."""
    state = state_of(ctx)

    async def inner() -> int:
        backend = state.state_backend()
        await backend.initialize()
        try:
            async with state.build_fleet(state_backend=backend) as fleet:
                sync_plan = await fleet.plan_sync(job)
                state.emit(
                    "sync-plan",
                    sync_plan,
                    render=lambda console: render_sync_plan(console, sync_plan),
                )
                if dry_run:
                    return EXIT_PLAN if sync_plan.blocked else EXIT_SUCCESS
                result = await fleet.apply_sync(sync_plan)
                state.emit(
                    "sync-result",
                    result,
                    render=lambda console: render_sync_result(console, result),
                )
                return EXIT_SUCCESS if result.complete else EXIT_PARTIAL
        finally:
            await backend.close()

    run(state, inner())
