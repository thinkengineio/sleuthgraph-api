"""Shared FastAPI dependencies for the plugin router."""

from sleuthgraph.evidence.deps import get_storage
from sleuthgraph.plugins import PLUGINS
from sleuthgraph.plugins.registry import PluginRegistry

# Built once at import time (plugin list is static)
_registry = PluginRegistry(PLUGINS)


def get_registry() -> PluginRegistry:
    """Tests override this to swap in a registry with fake plugins."""
    return _registry


# get_storage re-exported so tests can still override on the same dep key
__all__ = ["get_registry", "get_storage"]
