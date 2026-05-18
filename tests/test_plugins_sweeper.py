"""Tests for the stuck-running PluginRun sweeper."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.cases.models import Case
from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.models import PluginRun
from sleuthgraph.plugins.sweeper import sweep_stuck_runs


@pytest.fixture
async def sqlite_db(test_engine):
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as s:
        yield s


@pytest.fixture
async def seeded(sqlite_db):
    """Create user + case + entity for PluginRun FK requirements."""
    u = User(
        id=uuid.uuid4(), email="sweep@x.com", hashed_password="x",
        is_active=True, is_superuser=False, is_verified=False,
    )
    sqlite_db.add(u)
    await sqlite_db.commit()

    case = Case(owner_id=u.id, name="Sweeper test", tags=[])
    sqlite_db.add(case)
    await sqlite_db.commit()
    await sqlite_db.refresh(case)

    entity = Entity(
        case_id=case.id, type=EntityType.DOMAIN.value, label="example.com",
        attrs={}, confidence=1.0, created_by=u.id,
    )
    sqlite_db.add(entity)
    await sqlite_db.commit()
    await sqlite_db.refresh(entity)
    return u, case, entity


@pytest.mark.asyncio
async def test_sweeper_marks_stale_running_as_failed(sqlite_db, seeded):
    """A running row older than the threshold gets swept to failed."""
    user, case, entity = seeded
    stale_time = datetime.now(timezone.utc) - timedelta(minutes=20)

    stale_run = PluginRun(
        case_id=case.id,
        input_entity_id=entity.id,
        plugin_name="test_plugin",
        plugin_version="0.0.1",
        status="running",
        started_at=stale_time,
        created_by=user.id,
    )
    sqlite_db.add(stale_run)
    await sqlite_db.commit()
    await sqlite_db.refresh(stale_run)

    count = await sweep_stuck_runs(sqlite_db, threshold_minutes=10)
    assert count == 1

    await sqlite_db.refresh(stale_run)
    assert stale_run.status == "failed"
    assert stale_run.error_message == "Timed out — marked stale by sweeper"
    assert stale_run.finished_at is not None


@pytest.mark.asyncio
async def test_sweeper_marks_stale_queued_as_failed(sqlite_db, seeded):
    """A queued row older than the threshold also gets swept."""
    user, case, entity = seeded
    stale_time = datetime.now(timezone.utc) - timedelta(minutes=15)

    queued_run = PluginRun(
        case_id=case.id,
        input_entity_id=entity.id,
        plugin_name="test_plugin",
        plugin_version="0.0.1",
        status="queued",
        started_at=stale_time,
        created_by=user.id,
    )
    sqlite_db.add(queued_run)
    await sqlite_db.commit()
    await sqlite_db.refresh(queued_run)

    count = await sweep_stuck_runs(sqlite_db, threshold_minutes=10)
    assert count == 1

    await sqlite_db.refresh(queued_run)
    assert queued_run.status == "failed"


@pytest.mark.asyncio
async def test_sweeper_does_not_touch_fresh_runs(sqlite_db, seeded):
    """A running row within the threshold is left alone."""
    user, case, entity = seeded
    recent_time = datetime.now(timezone.utc) - timedelta(minutes=2)

    fresh_run = PluginRun(
        case_id=case.id,
        input_entity_id=entity.id,
        plugin_name="test_plugin",
        plugin_version="0.0.1",
        status="running",
        started_at=recent_time,
        created_by=user.id,
    )
    sqlite_db.add(fresh_run)
    await sqlite_db.commit()
    await sqlite_db.refresh(fresh_run)

    count = await sweep_stuck_runs(sqlite_db, threshold_minutes=10)
    assert count == 0

    await sqlite_db.refresh(fresh_run)
    assert fresh_run.status == "running"


@pytest.mark.asyncio
async def test_sweeper_does_not_touch_succeeded_or_failed(sqlite_db, seeded):
    """Already-terminal rows are never modified, even if old."""
    user, case, entity = seeded
    old_time = datetime.now(timezone.utc) - timedelta(hours=1)

    succeeded_run = PluginRun(
        case_id=case.id,
        input_entity_id=entity.id,
        plugin_name="test_plugin",
        plugin_version="0.0.1",
        status="succeeded",
        started_at=old_time,
        finished_at=old_time + timedelta(seconds=5),
        created_by=user.id,
    )
    failed_run = PluginRun(
        case_id=case.id,
        input_entity_id=entity.id,
        plugin_name="test_plugin",
        plugin_version="0.0.1",
        status="failed",
        started_at=old_time,
        finished_at=old_time + timedelta(seconds=5),
        error_message="some error",
        created_by=user.id,
    )
    sqlite_db.add_all([succeeded_run, failed_run])
    await sqlite_db.commit()

    count = await sweep_stuck_runs(sqlite_db, threshold_minutes=10)
    assert count == 0

    await sqlite_db.refresh(succeeded_run)
    await sqlite_db.refresh(failed_run)
    assert succeeded_run.status == "succeeded"
    assert failed_run.status == "failed"


@pytest.mark.asyncio
async def test_sweeper_mixed_stale_and_fresh(sqlite_db, seeded):
    """Only the stale row is swept; the fresh one is untouched."""
    user, case, entity = seeded
    stale_time = datetime.now(timezone.utc) - timedelta(minutes=30)
    recent_time = datetime.now(timezone.utc) - timedelta(minutes=1)

    stale_run = PluginRun(
        case_id=case.id,
        input_entity_id=entity.id,
        plugin_name="test_plugin",
        plugin_version="0.0.1",
        status="running",
        started_at=stale_time,
        created_by=user.id,
    )
    fresh_run = PluginRun(
        case_id=case.id,
        input_entity_id=entity.id,
        plugin_name="test_plugin",
        plugin_version="0.0.1",
        status="running",
        started_at=recent_time,
        created_by=user.id,
    )
    sqlite_db.add_all([stale_run, fresh_run])
    await sqlite_db.commit()

    count = await sweep_stuck_runs(sqlite_db, threshold_minutes=10)
    assert count == 1

    await sqlite_db.refresh(stale_run)
    await sqlite_db.refresh(fresh_run)
    assert stale_run.status == "failed"
    assert fresh_run.status == "running"
