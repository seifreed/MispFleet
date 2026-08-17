"""OpenCTI integration commands."""

from __future__ import annotations

from typing import Annotated

import typer

from mispfleet.cli.context import EXIT_SUCCESS, CLIState, run, state_of
from mispfleet.credentials.base import default_resolver
from mispfleet.integrations import OpenCTIClient
from mispfleet.models.server import CredentialReference
from mispfleet.output.renderers import plain_text
from mispfleet.output.stix import event_to_stix_bundle

app = typer.Typer(help="Push MISP events to OpenCTI as STIX bundles.")


def _token(state: CLIState, key: str) -> str:
    resolver = default_resolver(interactive=not state.non_interactive)
    return resolver.resolve(CredentialReference(provider="env", key=key))


@app.command()
def test(
    ctx: typer.Context,
    opencti_url: Annotated[str, typer.Option("--opencti-url", help="OpenCTI base URL.")],
    credential_key: Annotated[
        str, typer.Option(help="Environment variable holding the OpenCTI token.")
    ],
) -> None:
    """Verify connectivity and authentication against OpenCTI."""
    state = state_of(ctx)

    async def inner() -> int:
        # Resolved inside the coroutine so a missing credential exits 3
        # through run() instead of escaping click as a traceback.
        token = _token(state, credential_key)
        async with OpenCTIClient(opencti_url, token) as client:
            version = await client.version()
        state.emit(
            "opencti-test",
            {"reachable": True, "version": version},
            render=lambda console: console.print(f"OpenCTI {plain_text(version)} reachable"),
        )
        return EXIT_SUCCESS

    run(state, inner())


@app.command()
def push(
    ctx: typer.Context,
    event_id: Annotated[str, typer.Argument(help="Event UUID or numeric id.")],
    opencti_url: Annotated[str, typer.Option("--opencti-url", help="OpenCTI base URL.")],
    credential_key: Annotated[
        str, typer.Option(help="Environment variable holding the OpenCTI token.")
    ],
) -> None:
    """Export one event to STIX and import it into OpenCTI (--server NAME)."""
    state = state_of(ctx)
    server = state.single_server()

    async def inner() -> int:
        # Resolved inside the coroutine so a missing credential exits 3
        # through run() instead of escaping click as a traceback.
        token = _token(state, credential_key)
        async with state.build_fleet() as fleet:
            event = await fleet.client(server).events.get(event_id)
        bundle, skipped = event_to_stix_bundle(event)
        async with OpenCTIClient(opencti_url, token) as client:
            work_id = await client.push_bundle(bundle)
        state.emit(
            "opencti-push",
            {"work_id": work_id, "skipped": skipped, "objects": len(bundle["objects"])},
            render=lambda console: console.print(
                f"imported {len(bundle['objects'])} object(s) into OpenCTI "
                f"(work {plain_text(work_id)})"
            ),
        )
        return EXIT_SUCCESS

    run(state, inner())
