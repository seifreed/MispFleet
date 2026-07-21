"""Unit tests for entry-point plugin discovery with real entry points."""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import EntryPoint, EntryPoints

import pytest

from mispfleet.plugins import (
    MispFleetPlugin,
    PluginCategory,
    PluginLoadError,
    discover_plugins,
    load_plugin,
)
from tests.support import contains, eq, ok

GROUP = "mispfleet.plugins"


def provider_with(**targets: str) -> EntryPoints:
    return EntryPoints(
        EntryPoint(name=name, value=value, group=GROUP) for name, value in targets.items()
    )


def make_provider(**targets: str) -> Callable[..., EntryPoints]:
    points = provider_with(**targets)

    def provider(group: str) -> EntryPoints:
        eq(group, GROUP)
        return points

    return provider


def test_discover_lists_advertised_plugins_without_importing() -> None:
    provider = make_provider(
        sample="tests.sample_plugin:SamplePlugin",
        broken="tests.sample_plugin:BrokenPlugin",
    )
    eq(
        discover_plugins(provider),
        {
            "sample": "tests.sample_plugin:SamplePlugin",
            "broken": "tests.sample_plugin:BrokenPlugin",
        },
    )


def test_load_plugin_instantiates_and_validates() -> None:
    provider = make_provider(sample="tests.sample_plugin:SamplePlugin")
    plugin = load_plugin("sample", provider)
    ok(isinstance(plugin, MispFleetPlugin))
    info = plugin.info()
    eq(info.category, PluginCategory.EXPORTER)
    eq(plugin.activate(), "sample-extension")


def test_load_plugin_reports_missing_plugin() -> None:
    provider = make_provider()
    with pytest.raises(PluginLoadError) as excinfo:
        load_plugin("ghost", provider)
    contains(str(excinfo.value), "ghost")


def test_load_plugin_isolates_construction_failures() -> None:
    provider = make_provider(broken="tests.sample_plugin:BrokenPlugin")
    with pytest.raises(PluginLoadError) as excinfo:
        load_plugin("broken", provider)
    contains(str(excinfo.value), "failed to load")


def test_load_plugin_rejects_non_conforming_objects() -> None:
    provider = make_provider(bad="tests.sample_plugin:NOT_A_PLUGIN")
    with pytest.raises(PluginLoadError) as excinfo:
        load_plugin("bad", provider)
    contains(str(excinfo.value), "protocol")


def test_default_discovery_runs_against_installed_metadata() -> None:
    eq(discover_plugins(), {})
