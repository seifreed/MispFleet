"""Unit tests for configuration loading."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mispfleet.exceptions import InvalidConfigurationError
from mispfleet.settings import (
    ENV_CONFIG,
    ENV_STATE,
    FleetDefaults,
    default_config_path,
    default_state_path,
    load_fleet_config,
)
from tests.support import contains, eq, ok

VALID_CONFIG = """
version: 1
defaults:
  verify_tls: true
  request_timeout: 42
servers:
  production:
    url: https://misp.example
    credential:
      provider: env
      key: MISPFLEET_PRODUCTION_API_KEY
    role: primary
    groups: [internal, all]
  partner-cert:
    url: https://misp.partner.example
    credential:
      provider: env
      key: MISPFLEET_PARTNER_API_KEY
    read_only: true
    groups: [partners, all]
policies:
  production-import:
    remove_tags: [internal-only]
    add_tags: ["imported-by:mispfleet"]
    reject_if:
      tags: ["tlp:red"]
profiles:
  lab:
    defaults:
      request_timeout: 5
"""


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "config.yml"
    path.write_text(content, encoding="utf-8")
    return path


def test_load_valid_config_applies_defaults(tmp_path: Path) -> None:
    config = load_fleet_config(write_config(tmp_path, VALID_CONFIG))
    eq(sorted(config.servers), ["partner-cert", "production"])
    production = config.servers["production"]
    eq(production.request_timeout, 42.0)
    eq(production.concurrency, 5)
    ok(config.servers["partner-cert"].read_only)
    eq(config.policies["production-import"].reject_if.tags, {"tlp:red"})


def test_load_config_with_profile_overrides_defaults(tmp_path: Path) -> None:
    path = write_config(tmp_path, VALID_CONFIG)
    config = load_fleet_config(path, profile="lab")
    eq(config.servers["production"].request_timeout, 5.0)


def test_profile_can_come_from_environment(tmp_path: Path) -> None:
    path = write_config(tmp_path, VALID_CONFIG)
    os.environ["MISPFLEET_PROFILE"] = "lab"
    try:
        config = load_fleet_config(path)
        eq(config.servers["production"].request_timeout, 5.0)
    finally:
        del os.environ["MISPFLEET_PROFILE"]


def test_unknown_profile_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, VALID_CONFIG)
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(path, profile="missing")
    contains(str(excinfo.value), "missing")


def test_missing_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(tmp_path / "absent.yml")
    contains(str(excinfo.value), "not found")


def test_invalid_yaml_is_reported(tmp_path: Path) -> None:
    path = write_config(tmp_path, "servers: [unclosed")
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(path)
    contains(str(excinfo.value), "invalid YAML")


def test_non_mapping_root_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(path)
    contains(str(excinfo.value), "mapping")


def test_empty_file_yields_empty_config(tmp_path: Path) -> None:
    config = load_fleet_config(write_config(tmp_path, ""))
    eq(config.servers, {})
    eq(config.defaults, FleetDefaults())


def test_unsupported_version_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, "version: 99\n")
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(path)
    contains(str(excinfo.value), "99")


def test_case_insensitive_duplicate_server_names_are_rejected(tmp_path: Path) -> None:
    content = """
servers:
  production:
    url: https://a.example
    credential: {provider: env, key: A}
  PRODUCTION:
    url: https://b.example
    credential: {provider: env, key: B}
"""
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(write_config(tmp_path, content))
    contains(str(excinfo.value), "duplicate")


def test_invalid_server_entry_is_reported_with_name(tmp_path: Path) -> None:
    content = """
servers:
  broken:
    url: not-a-url
    credential: {provider: env, key: A}
"""
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(write_config(tmp_path, content))
    contains(str(excinfo.value), "broken")


def test_non_mapping_server_entry_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(InvalidConfigurationError) as excinfo:
        load_fleet_config(write_config(tmp_path, "servers:\n  broken: 42\n"))
    contains(str(excinfo.value), "must be a mapping")


def test_invalid_defaults_are_reported(tmp_path: Path) -> None:
    with pytest.raises(InvalidConfigurationError):
        load_fleet_config(write_config(tmp_path, "defaults:\n  unexpected: true\n"))


def test_default_paths_honor_environment_overrides(tmp_path: Path) -> None:
    os.environ[ENV_CONFIG] = str(tmp_path / "override.yml")
    os.environ[ENV_STATE] = str(tmp_path / "override.db")
    try:
        eq(default_config_path(), tmp_path / "override.yml")
        eq(default_state_path(), tmp_path / "override.db")
    finally:
        del os.environ[ENV_CONFIG]
        del os.environ[ENV_STATE]
    contains(str(default_config_path()), "mispfleet")
    contains(str(default_state_path()), "mispfleet")
