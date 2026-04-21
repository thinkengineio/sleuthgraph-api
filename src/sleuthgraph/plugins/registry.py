"""In-memory plugin registry — dict of {name: OSINTPlugin instance}.

Plugins ship with code (no DB registration). App startup iterates over
``PLUGINS`` (see ``sleuthgraph.plugins.__init__``) and builds the registry.
"""

from __future__ import annotations

from sleuthgraph.plugins.base import OSINTPlugin


class PluginNotFoundError(KeyError):
    """Raised when a plugin name is looked up but isn't registered."""


class PluginRegistry:
    def __init__(self, plugins: list[OSINTPlugin] | None = None) -> None:
        self._plugins: dict[str, OSINTPlugin] = {}
        for p in plugins or []:
            self.register(p)

    def register(self, plugin: OSINTPlugin) -> None:
        if not plugin.name:
            raise ValueError("plugin must have a non-empty name")
        if plugin.name in self._plugins:
            raise ValueError(f"duplicate plugin name: {plugin.name}")
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> OSINTPlugin:
        if name not in self._plugins:
            raise PluginNotFoundError(name)
        return self._plugins[name]

    def list(self) -> list[OSINTPlugin]:
        return list(self._plugins.values())

    def __contains__(self, name: str) -> bool:
        return name in self._plugins
