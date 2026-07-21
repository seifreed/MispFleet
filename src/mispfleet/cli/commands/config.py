"""Configuration commands."""

from __future__ import annotations

import os
from typing import Annotated

import typer
from rich.console import Console
from ruamel.yaml import YAML

from mispfleet.cli.context import EXIT_CONFIGURATION, EXIT_SUCCESS, state_of
from mispfleet.credentials.keyring import KeyringCredentialProvider
from mispfleet.exceptions import CredentialResolutionError, InvalidConfigurationError
from mispfleet.output.serializers import jsonable
from mispfleet.redaction import redact_mapping
from mispfleet.settings import default_config_path

app = typer.Typer(help="Manage the fleet configuration file.")

CONFIG_TEMPLATE = """version: 1
defaults:
  verify_tls: true
  request_timeout: 60
  connect_timeout: 10
  concurrency: 5
servers: {}
policies: {}
"""


@app.command()
def init(
    ctx: typer.Context,
    force: Annotated[bool, typer.Option(help="Overwrite an existing file.")] = False,
) -> None:
    """Create a configuration file with restrictive permissions."""
    state = state_of(ctx)
    path = state.config_path or default_config_path()
    if path.exists() and not force:
        typer.echo(f"configuration already exists at {path}; use --force to overwrite", err=True)
        raise typer.Exit(EXIT_CONFIGURATION)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(CONFIG_TEMPLATE, encoding="utf-8")
    path.chmod(0o600)
    typer.echo(f"created {path}")


@app.command()
def show(ctx: typer.Context) -> None:
    """Show the validated configuration with credentials redacted."""
    state = state_of(ctx)
    config = state.load_config()
    payload = redact_mapping(jsonable(config.model_dump(mode="json")))
    state.emit(
        "config-show",
        {"config": payload},
        render=lambda console: console.print_json(data=payload),
    )


@app.command()
def validate(ctx: typer.Context) -> None:
    """Validate the configuration and check credential references."""
    state = state_of(ctx)
    try:
        config = state.load_config()
    except InvalidConfigurationError as error:
        typer.echo(f"invalid configuration: {error.message}", err=True)
        raise typer.Exit(EXIT_CONFIGURATION) from error
    warnings: list[str] = []
    for name, server in config.servers.items():
        reference = server.credential
        if reference.provider == "env" and not os.environ.get(reference.key):
            warnings.append(f"server {name}: environment variable {reference.key} is not set")
        elif reference.provider == "keyring":
            try:
                KeyringCredentialProvider().resolve(reference.key)
            except CredentialResolutionError:
                warnings.append(f"server {name}: no keyring entry for {reference.key}")

    def render(console: Console) -> None:
        console.print(f"configuration valid: {len(config.servers)} server(s)")
        for warning in warnings:
            console.print(f"[yellow]warning[/yellow] {warning}")

    state.emit(
        "config-validate",
        {"valid": True, "servers": sorted(config.servers), "warnings": warnings},
        render=render,
    )


@app.command()
def path(ctx: typer.Context) -> None:
    """Print the effective configuration path."""
    state = state_of(ctx)
    typer.echo(str(state.config_path or default_config_path()))


@app.command("add-server")
def add_server(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Local server name.")],
    url: Annotated[str, typer.Option(help="Base URL of the MISP server.")],
    credential_key: Annotated[str, typer.Option(help="Credential key (e.g. env var name).")],
    credential_provider: Annotated[
        str, typer.Option(help="Credential provider: env, keyring, prompt or memory.")
    ] = "env",
    groups: Annotated[list[str] | None, typer.Option("--groups", help="Group membership.")] = None,
    role: Annotated[str, typer.Option(help="Server role.")] = "general",
    read_only: Annotated[bool, typer.Option(help="Mark the server read-only.")] = False,
) -> None:
    """Append a server to the configuration file."""
    state = state_of(ctx)
    config_path = state.config_path or default_config_path()
    yaml = YAML()
    data = yaml.load(config_path.read_text(encoding="utf-8")) if config_path.exists() else None
    if data is None:
        data = {"version": 1, "servers": {}}
    servers = data.setdefault("servers", {}) or {}
    if name in servers:
        typer.echo(f"server {name!r} already exists", err=True)
        raise typer.Exit(EXIT_CONFIGURATION)
    entry: dict[str, object] = {
        "url": url,
        "credential": {"provider": credential_provider, "key": credential_key},
        "role": role,
    }
    if groups:
        entry["groups"] = list(groups)
    if read_only:
        entry["read_only"] = True
    servers[name] = entry
    data["servers"] = servers
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with config_path.open("w", encoding="utf-8") as handle:
        yaml.dump(data, handle)
    config_path.chmod(0o600)
    typer.echo(f"added server {name!r} to {config_path}")


@app.command("remove-server")
def remove_server(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Local server name.")],
) -> None:
    """Remove a server from the configuration file."""
    state = state_of(ctx)
    config_path = state.config_path or default_config_path()
    if not config_path.exists():
        typer.echo(f"configuration file not found: {config_path}", err=True)
        raise typer.Exit(EXIT_CONFIGURATION)
    yaml = YAML()
    data = yaml.load(config_path.read_text(encoding="utf-8")) or {}
    servers = data.get("servers") or {}
    if name not in servers:
        typer.echo(f"server {name!r} is not configured", err=True)
        raise typer.Exit(EXIT_CONFIGURATION)
    del servers[name]
    with config_path.open("w", encoding="utf-8") as handle:
        yaml.dump(data, handle)
    typer.echo(f"removed server {name!r}")
    raise typer.Exit(EXIT_SUCCESS)
