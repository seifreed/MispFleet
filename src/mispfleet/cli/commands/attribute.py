"""Attribute commands: single fetch and streaming federated search."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, TextIO

import typer

from mispfleet.attachments import write_attachment
from mispfleet.cli.context import (
    EXIT_NO_MATCHES,
    EXIT_SUCCESS,
    CLIState,
    run,
    since_to_datetime,
    state_of,
)
from mispfleet.models.query import SearchQuery
from mispfleet.output.serializers import jsonable

app = typer.Typer(help="Work with attributes across the fleet.")


def _open_output(state: CLIState) -> TextIO:
    """The JSONL sink: stdout, or --output opened only once there is output."""
    if state.output_path is None:
        return sys.stdout
    try:
        return state.output_path.open("w", encoding="utf-8")
    except OSError as error:
        # emit() already reports an unwritable --output as a usage error; the
        # streaming path let the raw OSError escape as exit 1.
        raise typer.BadParameter(f"cannot write {state.output_path}: {error}") from error


@app.command()
def get(
    ctx: typer.Context,
    attribute_id: Annotated[str, typer.Argument(help="Attribute UUID or numeric id.")],
    download: Annotated[
        Path | None,
        typer.Option("--download", help="Save the attachment payload into this directory."),
    ] = None,
) -> None:
    """Fetch one attribute from one server (--server NAME)."""
    state = state_of(ctx)
    server = state.single_server()

    async def inner() -> int:
        async with state.build_fleet() as fleet:
            attribute = await fleet.client(server).attributes.get(attribute_id)
        payload: dict[str, object] = {"server": server, "attribute": attribute}
        if download is not None:
            if attribute.data is None:
                state.emit("attribute-get", payload | {"saved_to": None})
                return EXIT_NO_MATCHES
            filename = attribute.value.split("|", 1)[0]
            saved = write_attachment(attribute.data, download, filename)
            payload["saved_to"] = str(saved)
        state.emit(
            "attribute-get",
            payload,
            render=lambda console: console.print_json(data=attribute.model_dump(mode="json")),
        )
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def search(
    ctx: typer.Context,
    attribute_type: Annotated[
        list[str] | None, typer.Option("--type", help="Attribute type filter.")
    ] = None,
    tag: Annotated[list[str] | None, typer.Option(help="Require this tag.")] = None,
    since: Annotated[str | None, typer.Option(help="Relative window, e.g. 7d.")] = None,
    limit: Annotated[int | None, typer.Option(min=1, help="Maximum records per server.")] = None,
    page_size: Annotated[int, typer.Option(min=1, help="Records fetched per page.")] = 1000,
) -> None:
    """Stream matching attributes as JSON lines without buffering the dataset."""
    state = state_of(ctx)
    query = SearchQuery(
        attribute_types=set(attribute_type or []),
        tags=set(tag or []),
        date_from=since_to_datetime(since) if since else None,
        limit_per_server=limit,
    )

    async def inner() -> int:
        count = 0
        # Opened on the first record, not up front: "w" truncates, so an
        # unknown selector or an unreachable fleet destroyed the previous
        # contents of --output before any work had been attempted. emit()
        # writes only once the operation succeeded; this now matches it.
        stream: TextIO | None = None
        try:
            async with state.build_fleet() as fleet:
                async for match in fleet.iter_search(
                    query, selector=state.selector(), page_size=page_size
                ):
                    # jsonable, not model_dump: the latter leaves a set in hash
                    # order, so the one command built for piping emitted
                    # different bytes for the same data on every run.
                    record = jsonable(match.model_dump(exclude={"raw"}))
                    if stream is None:
                        stream = _open_output(state)
                    stream.write(json.dumps(record, sort_keys=True) + "\n")
                    count += 1
            if stream is None:
                # An empty result is still a result: the file is created, just
                # not before the fleet has answered.
                stream = _open_output(state)
            # Flushed inside the try: stdout to a pipe is block-buffered, so
            # without this the broken pipe surfaced during interpreter
            # shutdown instead — past the handler, exiting 120.
            stream.flush()
        except BrokenPipeError:
            # `mispfleet attribute search | head` closes the pipe: nothing
            # failed, and every other output path already reports that as 0.
            state.discard_closed_stdout()
        finally:
            if stream is not None and state.output_path is not None:
                stream.close()
        return EXIT_SUCCESS if count else EXIT_NO_MATCHES

    run(state, inner())
