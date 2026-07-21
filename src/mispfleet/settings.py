"""Configuration loading: YAML file, profiles, defaults and standard paths."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import platformdirs
from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from mispfleet.exceptions import InvalidConfigurationError
from mispfleet.models.server import ServerConfig
from mispfleet.policies.base import PolicySpec

APP_NAME = "mispfleet"
SUPPORTED_CONFIG_VERSION = 1

ENV_CONFIG = "MISPFLEET_CONFIG"
ENV_STATE = "MISPFLEET_STATE_PATH"
ENV_PROFILE = "MISPFLEET_PROFILE"


class FleetDefaults(BaseModel):
    """Fleet-wide defaults applied to servers that do not override them."""

    model_config = ConfigDict(extra="forbid")

    verify_tls: bool = True
    request_timeout: float = Field(default=60.0, gt=0.0)
    connect_timeout: float = Field(default=10.0, gt=0.0)
    concurrency: int = Field(default=5, ge=1)


class FleetConfig(BaseModel):
    """Validated fleet configuration: servers, defaults and policies."""

    version: int = SUPPORTED_CONFIG_VERSION
    defaults: FleetDefaults = Field(default_factory=FleetDefaults)
    servers: dict[str, ServerConfig] = Field(default_factory=dict)
    policies: dict[str, PolicySpec] = Field(default_factory=dict)


def default_config_path() -> Path:
    """Resolve the platform config path, honoring ``MISPFLEET_CONFIG``."""
    override = os.environ.get(ENV_CONFIG)
    if override:
        return Path(override)
    return platformdirs.user_config_path(APP_NAME) / "config.yml"


def default_state_path() -> Path:
    """Resolve the platform state path, honoring ``MISPFLEET_STATE_PATH``."""
    override = os.environ.get(ENV_STATE)
    if override:
        return Path(override)
    return platformdirs.user_state_path(APP_NAME) / "state.db"


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``override`` on top of ``base``."""
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise InvalidConfigurationError(f"configuration file not found: {path}")
    try:
        data = YAML(typ="safe").load(path.read_text(encoding="utf-8"))
    except YAMLError as error:
        raise InvalidConfigurationError(f"invalid YAML in {path}: {error}") from error
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise InvalidConfigurationError(f"configuration root must be a mapping: {path}")
    return dict(data)


def _apply_profile(data: dict[str, Any], profile: str | None) -> dict[str, Any]:
    profiles = data.pop("profiles", {}) or {}
    if profile is None:
        return data
    if profile not in profiles:
        raise InvalidConfigurationError(f"unknown configuration profile {profile!r}")
    return _merge(data, dict(profiles[profile]))


def _build_servers(
    raw_servers: dict[str, Any],
    defaults: FleetDefaults,
) -> dict[str, ServerConfig]:
    servers: dict[str, ServerConfig] = {}
    seen_lower: set[str] = set()
    for name, entry in raw_servers.items():
        lowered = str(name).lower()
        if lowered in seen_lower:
            raise InvalidConfigurationError(f"duplicate server name {name!r}")
        seen_lower.add(lowered)
        if not isinstance(entry, dict):
            raise InvalidConfigurationError(f"server {name!r} must be a mapping")
        merged = {**defaults.model_dump(), **entry, "name": str(name)}
        try:
            servers[str(name)] = ServerConfig.model_validate(merged)
        except PydanticValidationError as error:
            raise InvalidConfigurationError(f"invalid server {name!r}: {error}") from error
    return servers


def load_fleet_config(path: Path | None = None, profile: str | None = None) -> FleetConfig:
    """Load and validate the fleet configuration file.

    Precedence: explicit arguments > environment > profile > file > defaults.
    """
    config_path = path or default_config_path()
    profile = profile or os.environ.get(ENV_PROFILE) or None
    data = _apply_profile(_read_yaml(config_path), profile)
    version = data.get("version", SUPPORTED_CONFIG_VERSION)
    if version != SUPPORTED_CONFIG_VERSION:
        raise InvalidConfigurationError(f"unsupported configuration version {version!r}")
    try:
        defaults = FleetDefaults.model_validate(data.get("defaults") or {})
        policies = {
            str(name): PolicySpec.model_validate(spec or {})
            for name, spec in (data.get("policies") or {}).items()
        }
    except PydanticValidationError as error:
        raise InvalidConfigurationError(str(error)) from error
    servers = _build_servers(data.get("servers") or {}, defaults)
    return FleetConfig(version=version, defaults=defaults, servers=servers, policies=policies)
