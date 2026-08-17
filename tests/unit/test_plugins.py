"""Unit tests for entry-point plugin discovery with real entry points."""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import EntryPoint, EntryPoints

import pytest

from mispfleet.cli.commands.plugins import record_plugins
from mispfleet.plugins import (
    MispFleetPlugin,
    PluginCategory,
    PluginInfo,
    PluginLoadError,
    discover_plugins,
    load_plugin,
)
from mispfleet.plugins.loader import _ensure_compatible
from mispfleet.state import MemoryStateBackend
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


async def test_record_plugins_persists_discovered_entry_points() -> None:
    backend = MemoryStateBackend()
    await record_plugins(
        backend, {"beta": "pkg.beta:Plugin", "alpha": "tests.sample_plugin:SamplePlugin"}
    )
    stored = await backend.list_plugins()
    eq([record.name for record in stored], ["alpha", "beta"])
    eq(stored[0].target, "tests.sample_plugin:SamplePlugin")
    await record_plugins(backend, {})
    eq(len(await backend.list_plugins()), 2)


def test_incompatible_plugins_are_refused() -> None:
    provider = make_provider(incompatible="tests.sample_plugin:IncompatiblePlugin")
    with pytest.raises(PluginLoadError) as refused:
        load_plugin("incompatible", provider=provider)
    contains(str(refused.value), ">=9.0")


def test_unparsable_compatibility_is_refused() -> None:
    provider = make_provider(unparsable="tests.sample_plugin:UnparsableCompatibilityPlugin")
    with pytest.raises(PluginLoadError) as refused:
        load_plugin("unparsable", provider=provider)
    contains(str(refused.value), "unparsable compatibility")


def test_plugin_that_cannot_describe_itself_is_refused() -> None:
    provider = make_provider(undescribable="tests.sample_plugin:UndescribablePlugin")
    with pytest.raises(PluginLoadError) as refused:
        load_plugin("undescribable", provider=provider)
    contains(str(refused.value), "failed to describe itself")


def test_empty_compatibility_specifier_is_rejected() -> None:
    """SpecifierSet("") contains every version, so the gate never fired."""
    info = PluginInfo(
        name="empty",
        version="1.0",
        compatible_with="   ",
        category=PluginCategory.POLICY,
    )
    with pytest.raises(PluginLoadError) as excinfo:
        _ensure_compatible("empty", info)
    contains(str(excinfo.value), "empty compatibility")


def test_a_name_claimed_by_two_distributions_is_refused_not_guessed() -> None:
    """Listing kept the last claimant while loading took the first.

    An operator inspecting the discovered target vetted one distribution and a
    different one executed, with nothing reporting the collision.
    """
    colliding = EntryPoints(
        (
            EntryPoint(name="acme", value="good_plugin.mod:Plugin", group=GROUP),
            EntryPoint(name="acme", value="evil_plugin.mod:Plugin", group=GROUP),
        )
    )

    def provider(group: str) -> EntryPoints:
        return colliding

    with pytest.raises(PluginLoadError) as discovery:
        discover_plugins(provider=provider)
    contains(str(discovery.value), "two distributions")
    with pytest.raises(PluginLoadError) as loading:
        load_plugin("acme", provider=provider)
    contains(str(loading.value), "two distributions")


def test_the_same_name_advertised_twice_with_one_target_is_not_a_collision() -> None:
    """A distribution listed twice on the path still resolves to one plugin."""
    duplicated = EntryPoints(
        (
            EntryPoint(name="acme", value="pkg.mod:Plugin", group=GROUP),
            EntryPoint(name="acme", value="pkg.mod:Plugin", group=GROUP),
        )
    )
    eq(discover_plugins(provider=lambda group: duplicated), {"acme": "pkg.mod:Plugin"})
