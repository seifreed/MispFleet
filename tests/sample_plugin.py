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
