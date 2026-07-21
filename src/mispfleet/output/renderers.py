"""Human-oriented terminal rendering built on rich."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from mispfleet.models.diff import EventDiff
from mispfleet.models.plan import ApplyResult, CopyPlan
from mispfleet.models.result import FederatedSearchResult, FleetHealthResult
from mispfleet.models.server import ServerConfig


def _status_table(title: str, columns: list[str]) -> Table:
    table = Table(title=title, show_lines=False)
    for column in columns:
        table.add_column(column)
    return table


def render_servers(console: Console, servers: list[ServerConfig]) -> None:
    """Render the configured server list."""
    table = _status_table("Servers", ["name", "url", "role", "groups", "enabled", "read-only"])
    for server in servers:
        table.add_row(
            server.name,
            str(server.url),
            server.role.value,
            ",".join(sorted(server.groups)),
            "yes" if server.enabled else "no",
            "yes" if server.read_only else "no",
        )
    console.print(table)


def render_search_result(console: Console, result: FederatedSearchResult) -> None:
    """Render federated matches with per-server statuses."""
    table = _status_table(
        f"Matches ({result.total_matches})",
        ["server", "type", "value", "event", "tags"],
    )
    for match in result.matches:
        table.add_row(
            match.server,
            match.attribute_type or "",
            match.value or "",
            str(match.event_uuid or match.event_id or ""),
            ",".join(sorted(match.tags)),
        )
    console.print(table)
    _render_server_statuses(console, result.successful_servers, result.failed_servers)
    if result.groups:
        console.print(f"{len(result.groups)} duplicate group(s) detected")


def _render_server_statuses(console: Console, successful: list[str], failed: list[str]) -> None:
    for server in successful:
        console.print(f"[green]ok[/green] {server}")
    for server in failed:
        console.print(f"[red]failed[/red] {server}")


def render_health(console: Console, result: FleetHealthResult) -> None:
    """Render fleet health with warnings separated from failures."""
    table = _status_table(
        "Fleet health",
        ["server", "reachable", "authenticated", "latency", "version", "capabilities"],
    )
    for name in result.requested_servers:
        health = result.results.get(name)
        if health is None:
            error = result.errors.get(name)
            table.add_row(name, "no", "-", "-", "-", error.message if error else "")
            continue
        table.add_row(
            health.server,
            "yes" if health.reachable else "no",
            "yes" if health.authenticated else "no",
            f"{health.latency_ms:.0f} ms" if health.latency_ms is not None else "-",
            health.misp_version or "-",
            ",".join(sorted(health.capabilities)),
        )
    console.print(table)
    for name in result.requested_servers:
        health = result.results.get(name)
        if health is not None:
            for warning in health.warnings:
                console.print(f"[yellow]warning[/yellow] {name}: {warning}")
            if health.error is not None:
                console.print(f"[red]error[/red] {name}: {health.error.message}")


def render_diff(console: Console, diff: EventDiff) -> None:
    """Render an event diff."""
    if diff.equivalent:
        console.print(
            f"event {diff.event_identifier} is equivalent on "
            f"{diff.left_server} and {diff.right_server}"
        )
        return
    table = _status_table(
        f"Diff {diff.left_server} vs {diff.right_server}",
        ["operation", "path", "left", "right"],
    )
    for difference in diff.differences:
        table.add_row(
            difference.operation.value,
            difference.path,
            "" if difference.left is None else str(difference.left),
            "" if difference.right is None else str(difference.right),
        )
    console.print(table)
    summary = diff.summary
    console.print(
        f"added={summary.added} removed={summary.removed} "
        f"changed={summary.changed} conflicts={summary.conflicts}"
    )


def render_plan(console: Console, plan: CopyPlan) -> None:
    """Render a copy plan review."""
    console.print(
        f"Plan {plan.plan_id}: copy {plan.source_event_uuid} "
        f"from {plan.source_server} to {plan.destination_server}"
    )
    for transformation in plan.transformations:
        console.print(f"  transform: {transformation.action} {transformation.target}")
    for validation in plan.validations:
        status = "[green]pass[/green]" if validation.passed else "[red]fail[/red]"
        console.print(f"  validate: {validation.name} {status} {validation.message}")
    for warning in plan.warnings:
        console.print(f"  [yellow]warning[/yellow]: {warning.message}")
    for issue in plan.blocking_errors:
        console.print(f"  [red]blocking[/red]: {issue.code}: {issue.message}")


def render_apply_result(console: Console, result: ApplyResult) -> None:
    """Render the outcome of applying a plan."""
    status = "applied" if result.applied else "not applied"
    console.print(f"Plan {result.plan_id}: {status} on {result.destination_server}")
    for message in result.messages:
        console.print(f"  {message}")
