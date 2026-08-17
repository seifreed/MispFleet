"""A real plugin implementation used by the loader tests."""

from __future__ import annotations

from mispfleet.plugins.protocol import PluginCategory, PluginInfo


class SamplePlugin:
    """Minimal, fully functional plugin."""

    def info(self) -> PluginInfo:
        return PluginInfo(
            name="sample",
            version="1.0.0",
            category=PluginCategory.EXPORTER,
            compatible_with=">=0.1",
        )

    def activate(self) -> str:
        return "sample-extension"


class BrokenPlugin:
    """A plugin whose construction fails."""

    def __init__(self) -> None:
        raise RuntimeError("boom at construction time")


NOT_A_PLUGIN = "just a string"


class IncompatiblePlugin:
    """A plugin built for a MispFleet major version that is not this one."""

    def info(self) -> PluginInfo:
        return PluginInfo(
            name="incompatible",
            version="1.0.0",
            category=PluginCategory.POLICY,
            compatible_with=">=9.0",
        )

    def activate(self) -> str:
        return "never-activated"


class UnparsableCompatibilityPlugin:
    """A plugin whose compatibility declaration is not a valid specifier."""

    def info(self) -> PluginInfo:
        return PluginInfo(
            name="unparsable",
            version="1.0.0",
            category=PluginCategory.POLICY,
            compatible_with="whatever works",
        )

    def activate(self) -> str:
        return "never-activated"


class UndescribablePlugin:
    """A plugin whose metadata call blows up."""

    def info(self) -> PluginInfo:
        raise RuntimeError("boom while describing")

    def activate(self) -> str:
        return "never-activated"
