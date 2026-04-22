"""arq WorkerSettings lazy-loads Redis settings.

Regression: prior to Code-Important-1 fix, importing
``sleuthgraph.queue.arq_settings`` immediately called
``get_settings().effective_arq_redis_url`` at module-load time, which
meant:
  1. Tests without REDIS_URL in env would fail to import the module.
  2. A misconfigured worker would crash on import rather than surface
     a clear error when the pool was actually needed.

The fix replaces the class-level value with a ``_LazyRedisSettings``
descriptor; settings are resolved only when the attribute is read.
"""

from __future__ import annotations

import sys
import types

import pytest


def test_import_does_not_touch_settings(monkeypatch):
    """Importing arq_settings must not call get_settings().

    If get_settings raises, the import must still succeed; the cost of
    resolving Redis URL is deferred to first real access.
    """
    # Ensure we actually re-import (not hit a cached module)
    sys.modules.pop("sleuthgraph.queue.arq_settings", None)

    # Force get_settings() to raise — if the module called it at import
    # time the test would fail here.
    from sleuthgraph import config as config_mod

    def _boom():
        raise RuntimeError("get_settings must not be called during import")

    monkeypatch.setattr(config_mod, "get_settings", _boom)

    import importlib

    mod = importlib.import_module("sleuthgraph.queue.arq_settings")
    # WorkerSettings symbol exists and is a class.
    assert isinstance(mod.WorkerSettings, type)
    # Class-level attributes that DO NOT hit Settings resolve fine.
    assert mod.WorkerSettings.max_jobs == 10
    assert mod.WorkerSettings.job_timeout == 300


def test_redis_settings_resolved_on_access(monkeypatch):
    """Reading WorkerSettings.redis_settings triggers get_settings()."""
    # Reset module so the descriptor is fresh.
    sys.modules.pop("sleuthgraph.queue.arq_settings", None)

    import importlib

    mod = importlib.import_module("sleuthgraph.queue.arq_settings")

    rs = mod.WorkerSettings.redis_settings
    # arq.connections.RedisSettings shape
    assert hasattr(rs, "host")
    assert hasattr(rs, "port")


def test_redis_settings_error_surfaces_on_access(monkeypatch):
    """If Settings resolution raises, the error must appear at access, not at import."""
    sys.modules.pop("sleuthgraph.queue.arq_settings", None)

    import importlib

    mod = importlib.import_module("sleuthgraph.queue.arq_settings")

    # Now swap get_settings to raise and confirm access path surfaces it.
    fake = types.SimpleNamespace()

    def _boom():
        raise RuntimeError("simulated settings failure")

    monkeypatch.setattr(mod, "get_settings", _boom)
    with pytest.raises(RuntimeError, match="simulated settings failure"):
        _ = mod.WorkerSettings.redis_settings
