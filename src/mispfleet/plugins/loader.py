"""Entry-point based plugin discovery with failure isolation."""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import EntryPoints, entry_points

from mispfleet.exceptions import MispFleetError
from mispfleet.logging import get_logger
from mispfleet.plugins.protocol import MispFleetPlugin

ENTRY_POINT_GROUP = "mispfleet.plugins"

logger = get_logger("plugins")

EntryPointProvider = Callable[..., EntryPoints]


class PluginLoadError(MispFleetError):
    """A plugin failed to load or does not satisfy the contract."""


def discover_plugins(provider: EntryPointProvider = entry_points) -> dict[str, str]:
    """List advertised plugins as ``{name: target}`` without importing them."""
    return {point.name: point.value for point in provider(group=ENTRY_POINT_GROUP)}


def load_plugin(name: str, provider: EntryPointProvider = entry_points) -> MispFleetPlugin:
    """Explicitly load and validate one plugin; failures never propagate raw."""
    matches = [point for point in provider(group=ENTRY_POINT_GROUP) if point.name == name]
    if not matches:
        raise PluginLoadError(f"no plugin named {name!r} is installed")
    try:
        loaded = matches[0].load()
        plugin: object = loaded() if isinstance(loaded, type) else loaded
    except Exception as error:
        logger.warning("plugin %s failed to load: %s", name, error)
        raise PluginLoadError(f"plugin {name!r} failed to load: {error}") from error
    if not isinstance(plugin, MispFleetPlugin):
        raise PluginLoadError(f"plugin {name!r} does not implement the MispFleet plugin protocol")
    return plugin
