"""Entry-point based plugin discovery with failure isolation."""

from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import EntryPoints, entry_points

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version

from mispfleet._version import __version__
from mispfleet.exceptions import MispFleetError
from mispfleet.logging import get_logger
from mispfleet.plugins.protocol import MispFleetPlugin, PluginInfo

ENTRY_POINT_GROUP = "mispfleet.plugins"

logger = get_logger("plugins")

EntryPointProvider = Callable[..., EntryPoints]


class PluginLoadError(MispFleetError):
    """A plugin failed to load or does not satisfy the contract."""


def discover_plugins(provider: EntryPointProvider = entry_points) -> dict[str, str]:
    """List advertised plugins as ``{name: target}`` without importing them."""
    discovered: dict[str, str] = {}
    for point in provider(group=ENTRY_POINT_GROUP):
        # Two distributions may advertise the same name. Listing kept the last
        # and loading took the first, so the operator vetted one target and a
        # different one ran. Neither is a safe guess: report both instead.
        if point.name in discovered and discovered[point.name] != point.value:
            raise PluginLoadError(
                f"plugin name {point.name!r} is claimed by two distributions "
                f"({discovered[point.name]} and {point.value}); uninstall one"
            )
        discovered[point.name] = point.value
    return discovered


def load_plugin(name: str, provider: EntryPointProvider = entry_points) -> MispFleetPlugin:
    """Explicitly load and validate one plugin; failures never propagate raw."""
    matches = [point for point in provider(group=ENTRY_POINT_GROUP) if point.name == name]
    if not matches:
        raise PluginLoadError(f"no plugin named {name!r} is installed")
    targets = {point.value for point in matches}
    if len(targets) > 1:
        raise PluginLoadError(
            f"plugin name {name!r} is claimed by two distributions "
            f"({', '.join(sorted(targets))}); uninstall one"
        )
    try:
        loaded = matches[0].load()
        plugin: object = loaded() if isinstance(loaded, type) else loaded
    except Exception as error:
        logger.warning("plugin %s failed to load: %s", name, error)
        raise PluginLoadError(f"plugin {name!r} failed to load: {error}") from error
    if not isinstance(plugin, MispFleetPlugin):
        raise PluginLoadError(f"plugin {name!r} does not implement the MispFleet plugin protocol")
    try:
        info = plugin.info()
    except Exception as error:
        logger.warning("plugin %s failed to describe itself: %s", name, error)
        raise PluginLoadError(f"plugin {name!r} failed to describe itself: {error}") from error
    _ensure_compatible(name, info)
    return plugin


def _ensure_compatible(name: str, info: PluginInfo) -> None:
    """Enforce the plugin's declared compatibility against this MispFleet.

    A declaration that is never checked is worse than none: it lets a plugin
    built for another major version activate silently.
    """
    if not info.compatible_with.strip():
        raise PluginLoadError(
            f"plugin {name!r} declares an empty compatibility specifier, "
            "which would match every MispFleet version"
        )
    try:
        specifier = SpecifierSet(info.compatible_with)
    except InvalidSpecifier as error:
        raise PluginLoadError(
            f"plugin {name!r} declares an unparsable compatibility "
            f"{info.compatible_with!r}: {error}"
        ) from error
    if Version(__version__) not in specifier:
        raise PluginLoadError(
            f"plugin {name!r} requires MispFleet {info.compatible_with}, "
            f"but this is {__version__}"
        )
