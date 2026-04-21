"""Plugin system: OSINTPlugin base + in-memory registry (Phase 5)."""

from sleuthgraph.plugins.builtin.crtsh import CrtShPlugin

PLUGINS: list = [
    CrtShPlugin(),
]
