"""Enqueue helper — bridge between HTTP request handlers and arq worker.

One shared ArqRedis pool per process, created lazily on first enqueue.
An ``asyncio.Lock`` guards initialization to prevent the narrow window
where two concurrent requests could both pass the ``is None`` check and
spin up redundant pools (security M-8 / Code-Important-2).

``close_pool()`` is wired into the FastAPI shutdown event so Redis
connections are released cleanly.
"""

from __future__ import annotations

import asyncio
import uuid

from arq import create_pool
from arq.connections import ArqRedis

from sleuthgraph.queue.arq_settings import WorkerSettings

_pool: ArqRedis | None = None
_pool_lock: asyncio.Lock = asyncio.Lock()


async def _get_pool() -> ArqRedis:
    global _pool
    async with _pool_lock:
        if _pool is None:
            _pool = await create_pool(WorkerSettings.redis_settings)
        return _pool


async def close_pool() -> None:
    """Close the shared arq pool — wired into FastAPI shutdown.

    Safe to call more than once; subsequent calls are no-ops.
    """
    global _pool
    async with _pool_lock:
        if _pool is not None:
            await _pool.close()
            _pool = None


async def enqueue_plugin_run(run_id: uuid.UUID) -> str:
    """Queue a plugin run. Returns the arq job id."""
    pool = await _get_pool()
    job = await pool.enqueue_job("run_plugin_task", str(run_id))
    if job is None:
        raise RuntimeError("arq enqueue returned None")
    return job.job_id
