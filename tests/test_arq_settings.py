"""arq WorkerSettings resolves redis settings eagerly at import time.

The class-level ``redis_settings`` calls ``get_settings()`` during class
definition.  This is intentional: arq's ``create_pool`` accesses
attributes on the class directly in ways that bypass descriptor protocol.

Tests verify the module loads correctly when env vars are set (handled
by conftest ``_set_env`` fixture) and that the resulting WorkerSettings
has the expected shape.
"""

from __future__ import annotations

import sys


def test_import_produces_worker_settings():
    """Importing arq_settings yields a WorkerSettings with expected attrs."""
    sys.modules.pop("sleuthgraph.queue.arq_settings", None)

    import importlib

    mod = importlib.import_module("sleuthgraph.queue.arq_settings")
    assert isinstance(mod.WorkerSettings, type)
    assert mod.WorkerSettings.max_jobs == 10
    assert mod.WorkerSettings.job_timeout == 300


def test_redis_settings_resolved_on_import():
    """WorkerSettings.redis_settings is populated at import time."""
    sys.modules.pop("sleuthgraph.queue.arq_settings", None)

    import importlib

    mod = importlib.import_module("sleuthgraph.queue.arq_settings")
    rs = mod.WorkerSettings.redis_settings
    assert hasattr(rs, "host")
    assert hasattr(rs, "port")
