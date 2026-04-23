"""arq WorkerSettings — defines queue config + registered task list.

Start the worker with:
    arq sleuthgraph.queue.arq_settings.WorkerSettings

redis_settings is computed eagerly at module import because arq's
``create_pool`` accesses attributes on the class directly in ways that
bypass descriptor protocol — a lazy descriptor left redis_settings.host
unreadable and crashed the worker. Production always has env set; tests
use ``conftest.py`` to populate them before import.
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


class WorkerSettings:
    functions = [run_plugin_task]
    redis_settings = _redis_settings_from_url(get_settings().effective_arq_redis_url)
    max_jobs = 10
    job_timeout = 300  # 5 minutes per plugin run
    keep_result = 3600  # Result kept in Redis 1 hour for polling
