# Plugin development

Plugins are discovered through Python entry points and are **never activated
merely because a package is installed** — activation is always explicit.

## Declaring a plugin

```toml
[project.entry-points."mispfleet.plugins"]
my_plugin = "my_package.module:MyPlugin"
```

## Implementing the contract

```python
from mispfleet.plugins import PluginCategory, PluginInfo


class MyPlugin:
    def info(self) -> PluginInfo:
        return PluginInfo(
            name="my-plugin",
            version="1.0.0",
            category=PluginCategory.EXPORTER,
            compatible_with=">=0.1",
        )

    def activate(self) -> object:
        return MyExporter()
```

Categories: credential provider, policy, transformer, validator, exporter,
state backend, conflict resolver, enrichment provider.

## Loading

```python
from mispfleet.plugins import discover_plugins, load_plugin

available = discover_plugins()          # {name: "module:attr"} without importing
plugin = load_plugin("my_plugin")       # validated against the typed protocol
extension = plugin.activate()
```

Load failures are isolated: a broken plugin raises `PluginLoadError` with the
underlying cause and never crashes discovery of other plugins.
