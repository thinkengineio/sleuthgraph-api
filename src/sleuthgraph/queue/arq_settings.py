"""arq WorkerSettings — defines queue config + registered task list.

Start the worker with:
    arq sleuthgraph.queue.arq_settings.WorkerSettings

Design note:
    ``redis_settings`` is a descriptor so the Settings object is only
    touched when arq (or enqueue_plugin_run) actually reads the attribute.
    This keeps ``import sleuthgraph.queue.arq_settings`` side-effect-free so
    tests can import it without Redis env vars configured.
"""

from __future__ import annotations

from urllib.parse import urlparse

from arq.connections import RedisSettings

from sleuthgraph.config import get_settings
from sleuthgraph.queue.tasks import run_plugin_task


def _redis_settings_from_url(url: str) -> RedisSettings:
    parsed = urlparse(url)
    database = 0
    if parsed.path:
        stripped = parsed.path.lstrip("/")
        if stripped:
            try:
                database = int(stripped)
            except ValueError:
                database = 0
    return RedisSettings(
        host=parsed.hostname or "localhost",
        port=parsed.port or 6379,
        password=parsed.password,
        database=database,
    )


class _LazyRedisSettings:
    """Descriptor that resolves Settings on first read, not at import time.

    The arq CLI (``arq sleuthgraph.queue.arq_settings.WorkerSettings``)
    reads ``WorkerSettings.redis_settings`` — which triggers
    ``__get__`` and evaluates ``get_settings()`` only then.
    """

    def __get__(self, obj: object, cls: type | None = None) -> RedisSettings:
        return _redis_settings_from_url(get_settings().effective_arq_redis_url)


class WorkerSettings:
    functions = [run_plugin_task]
    redis_settings = _LazyRedisSettings()
    max_jobs = 10
    job_timeout = 300  # 5 minutes per plugin run
    keep_result = 3600  # Result kept in Redis 1 hour for polling
