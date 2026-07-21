"""Federated search commands."""

from __future__ import annotations

from typing import Annotated

import typer

from mispfleet.cli.context import (
    EXIT_NO_MATCHES,
    EXIT_PARTIAL,
    EXIT_SUCCESS,
    CLIState,
    run,
    since_to_datetime,
    state_of,
)
from mispfleet.models.query import SearchQuery
from mispfleet.models.result import FederatedSearchResult
from mispfleet.output.renderers import render_search_result

app = typer.Typer(help="Search across the fleet, preserving provenance.")


async def _search(state: CLIState, query: SearchQuery, operation: str) -> int:
    async with state.build_fleet() as fleet:
        result = await fleet.search(query, selector=state.selector())
    _emit(state, operation, result)
    if result.partial:
        return EXIT_PARTIAL
    if result.total_matches == 0:
        return EXIT_NO_MATCHES
    return EXIT_SUCCESS


def _emit(state: CLIState, operation: str, result: FederatedSearchResult) -> None:
    state.emit(
        operation,
        result,
        render=lambda console: render_search_result(console, result),
        jsonl_records=[match.model_dump(mode="json", exclude={"raw"}) for match in result.matches],
        partial=result.partial,
    )


@app.command()
def value(
    ctx: typer.Context,
    indicator: Annotated[str, typer.Argument(help="Indicator value to search for.")],
    limit: Annotated[int | None, typer.Option(help="Maximum records per server.")] = None,
) -> None:
    """Search one indicator value across the fleet."""
    state = state_of(ctx)
    query = SearchQuery(value=indicator, limit_per_server=limit)
    run(state, _search(state, query, "federated-search"))


@app.command()
def events(
    ctx: typer.Context,
    info: Annotated[str | None, typer.Option(help="Event info substring.")] = None,
    since: Annotated[str | None, typer.Option(help="Relative window, e.g. 30d.")] = None,
    tag: Annotated[list[str] | None, typer.Option(help="Require this event tag.")] = None,
) -> None:
    """Search events by metadata across the fleet."""
    state = state_of(ctx)
    query = SearchQuery(
        event_info=info,
        tags=set(tag or []),
        date_from=since_to_datetime(since) if since else None,
        metadata_only=True,
    )
    run(state, _search(state, query, "federated-event-search"))


@app.command()
def attributes(
    ctx: typer.Context,
    attribute_type: Annotated[
        list[str] | None, typer.Option("--type", help="Attribute type filter.")
    ] = None,
    tag: Annotated[list[str] | None, typer.Option(help="Require this tag.")] = None,
    since: Annotated[str | None, typer.Option(help="Relative window, e.g. 7d.")] = None,
    limit: Annotated[int | None, typer.Option(help="Maximum records per server.")] = None,
) -> None:
    """Search attributes by type, tag and date across the fleet."""
    state = state_of(ctx)
    query = SearchQuery(
        attribute_types=set(attribute_type or []),
        tags=set(tag or []),
        date_from=since_to_datetime(since) if since else None,
        limit_per_server=limit,
    )
    run(state, _search(state, query, "federated-attribute-search"))
