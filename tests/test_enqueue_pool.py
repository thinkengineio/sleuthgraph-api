"""Pool initialization race + shutdown tests for sleuthgraph.queue.enqueue.

Regression guards:
- Code-Important-2 / Security M-8: concurrent _get_pool() callers must
  share a single pool. Without the asyncio.Lock guarding init, two
  coroutines could both pass the ``is None`` check before either
  assigned the pool, spinning up redundant Redis connections.
- close_pool must be idempotent and must reset the module-global.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest


@pytest.fixture(autouse=True)
def _reset_pool():
    """Ensure each test starts with a clean _pool global."""
    from sleuthgraph.queue import enqueue

    enqueue._pool = None
    yield
    enqueue._pool = None


@pytest.mark.asyncio
async def test_concurrent_get_pool_creates_exactly_one_pool(monkeypatch):
    """Two concurrent callers of _get_pool must share one pool."""
    from sleuthgraph.queue import enqueue

    call_count = 0

    async def _fake_create_pool(_settings):
        nonlocal call_count
        call_count += 1
        # Simulate the async handshake — forces the event loop to
        # interleave other waiting tasks.
        await asyncio.sleep(0.01)
        return AsyncMock()

    monkeypatch.setattr(enqueue, "create_pool", _fake_create_pool)

    a, b, c = await asyncio.gather(
        enqueue._get_pool(),
        enqueue._get_pool(),
        enqueue._get_pool(),
    )

    assert call_count == 1, f"create_pool called {call_count}x — asyncio.Lock did not bound init"
    assert a is b is c, "concurrent callers should share the single pool instance"


@pytest.mark.asyncio
async def test_close_pool_is_idempotent(monkeypatch):
    from sleuthgraph.queue import enqueue

    fake_pool = AsyncMock()

    async def _fake_create_pool(_settings):
        return fake_pool

    monkeypatch.setattr(enqueue, "create_pool", _fake_create_pool)

    await enqueue._get_pool()
    await enqueue.close_pool()
    fake_pool.close.assert_awaited_once()

    # Second close — should be a no-op, not a second close call.
    await enqueue.close_pool()
    fake_pool.close.assert_awaited_once()
    assert enqueue._pool is None


@pytest.mark.asyncio
async def test_close_pool_without_get_pool_is_safe():
    """close_pool before any _get_pool must not raise."""
    from sleuthgraph.queue import enqueue

    await enqueue.close_pool()
    assert enqueue._pool is None
