"""Enqueue helper — bridge between HTTP request handlers and arq worker.

One shared ArqRedis pool per process, created lazily on first enqueue.
"""

from __future__ import annotations

import uuid

from arq import create_pool
from arq.connections import ArqRedis

from sleuthgraph.queue.arq_settings import WorkerSettings

_pool: ArqRedis | None = None


async def _get_pool() -> ArqRedis:
    global _pool
    if _pool is None:
        _pool = await create_pool(WorkerSettings.redis_settings)
    return _pool


async def enqueue_plugin_run(run_id: uuid.UUID) -> str:
    """Queue a plugin run. Returns the arq job id."""
    pool = await _get_pool()
    job = await pool.enqueue_job("run_plugin_task", str(run_id))
    if job is None:
        raise RuntimeError("arq enqueue returned None")
    return job.job_id
