"""Sweeper for stuck PluginRun rows.

PluginRun rows can get stuck in "running" or "queued" status if the worker
crashes mid-execution. This module provides a sweeper function that finds
stale rows and marks them as failed so they don't block the UI or confuse
operators.

Usage:
    from sleuthgraph.plugins.sweeper import sweep_stuck_runs

    count = await sweep_stuck_runs(session)          # default 10-minute threshold
    count = await sweep_stuck_runs(session, threshold_minutes=5)

Can be wired into an arq periodic task or a FastAPI startup background task.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.plugins.models import PluginRun

log = logging.getLogger(__name__)

_STALE_ERROR_MESSAGE = "Timed out — marked stale by sweeper"


async def sweep_stuck_runs(
    session: AsyncSession,
    *,
    threshold_minutes: int = 10,
) -> int:
    """Mark stale running/queued PluginRun rows as failed.

    A row is considered stale when its ``started_at`` is older than
    ``threshold_minutes`` and its status is still ``running`` or ``queued``.

    Returns the number of rows updated.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=threshold_minutes)

    stmt = (
        update(PluginRun)
        .where(
            PluginRun.status.in_(["running", "queued"]),
            PluginRun.started_at < cutoff,
        )
        .values(
            status="failed",
            finished_at=datetime.now(timezone.utc),
            error_message=_STALE_ERROR_MESSAGE,
        )
        .execution_options(synchronize_session=False)
    )
    result = await session.execute(stmt)
    await session.commit()

    count = result.rowcount  # type: ignore[union-attr]
    if count:
        log.info("sweeper marked %d stuck PluginRun(s) as failed", count)
    return count
