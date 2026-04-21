"""PluginRunRepository: case-scoped queries."""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.cases.models import Case
from sleuthgraph.plugins.models import PluginRun
from sleuthgraph.plugins.repository import PluginRunRepository


@pytest.fixture
async def sqlite_db(test_engine):
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as s:
        yield s


@pytest.fixture
async def seeded(sqlite_db):
    u = User(
        id=uuid.uuid4(), email="o@x.com", hashed_password="x",
        is_active=True, is_superuser=False, is_verified=False,
    )
    sqlite_db.add(u)
    await sqlite_db.commit()
    case = Case(owner_id=u.id, name="Test", tags=[])
    sqlite_db.add(case)
    await sqlite_db.commit()
    await sqlite_db.refresh(case)
    return u, case


async def _make_run(db, case_id, plugin_name, status, user_id):
    run = PluginRun(
        case_id=case_id, plugin_name=plugin_name, plugin_version="0.1",
        status=status, created_by=user_id,
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return run


@pytest.mark.asyncio
async def test_get_scoped_to_case(sqlite_db, seeded):
    user, case = seeded
    repo = PluginRunRepository(sqlite_db)
    r = await _make_run(sqlite_db, case.id, "crtsh", "succeeded", user.id)
    assert await repo.get(r.id, case.id) is not None
    assert await repo.get(r.id, uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_list_for_case(sqlite_db, seeded):
    user, case = seeded
    repo = PluginRunRepository(sqlite_db)
    await _make_run(sqlite_db, case.id, "crtsh", "succeeded", user.id)
    await _make_run(sqlite_db, case.id, "crtsh", "failed", user.id)
    await _make_run(sqlite_db, case.id, "other", "succeeded", user.id)
    items, total = await repo.list_for_case(case.id)
    assert total == 3
    assert len(items) == 3


@pytest.mark.asyncio
async def test_list_filter_status(sqlite_db, seeded):
    user, case = seeded
    repo = PluginRunRepository(sqlite_db)
    await _make_run(sqlite_db, case.id, "crtsh", "succeeded", user.id)
    await _make_run(sqlite_db, case.id, "crtsh", "failed", user.id)
    items, total = await repo.list_for_case(case.id, status="failed")
    assert total == 1
    assert items[0].status == "failed"


@pytest.mark.asyncio
async def test_list_filter_plugin_name(sqlite_db, seeded):
    user, case = seeded
    repo = PluginRunRepository(sqlite_db)
    await _make_run(sqlite_db, case.id, "crtsh", "succeeded", user.id)
    await _make_run(sqlite_db, case.id, "opencorp", "succeeded", user.id)
    items, total = await repo.list_for_case(case.id, plugin_name="opencorp")
    assert total == 1
    assert items[0].plugin_name == "opencorp"


@pytest.mark.asyncio
async def test_list_pagination(sqlite_db, seeded):
    user, case = seeded
    repo = PluginRunRepository(sqlite_db)
    for i in range(5):
        await _make_run(sqlite_db, case.id, f"p{i}", "succeeded", user.id)
    page1, total = await repo.list_for_case(case.id, limit=2, offset=0)
    assert total == 5
    assert len(page1) == 2
    page2, _ = await repo.list_for_case(case.id, limit=2, offset=2)
    assert len(page2) == 2
    assert not ({r.id for r in page1} & {r.id for r in page2})
