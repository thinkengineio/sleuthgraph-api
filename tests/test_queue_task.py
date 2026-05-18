"""run_plugin_task: idempotency + happy path + missing input entity."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.cases.models import Case
from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import (
    EntityProposal,
    EvidenceProposal,
    OSINTPlugin,
    QueryResult,
    RelationshipProposal,
)
from sleuthgraph.plugins.models import PluginRun
from sleuthgraph.plugins.registry import PluginRegistry
from sleuthgraph.queue.tasks import run_plugin_task
from sleuthgraph.relationships.types import RelationshipType


class _StubPlugin(OSINTPlugin):
    name = "stub_async"
    version = "0.0.1"
    entity_types_accepted = [EntityType.DOMAIN]
    entity_types_produced = [EntityType.DOMAIN]
    requires_credentials = False

    async def query(self, input_entity, credentials, context):
        return QueryResult(
            entities=[
                EntityProposal(ref="a", type=EntityType.DOMAIN, label="a.example.com"),
            ],
            relationships=[
                RelationshipProposal(
                    src={"ref": "a"},
                    dst={"input": True},
                    rel_type=RelationshipType.SUBDOMAIN_OF,
                ),
            ],
            evidence=[
                EvidenceProposal(query="q", payload=b"{}", content_type="application/json"),
            ],
        )


class _FakeStorage:
    def __init__(self):
        self._b = {}

    async def put(self, k, d, content_type="application/octet-stream"):
        self._b[k] = d

    async def get(self, k):
        return self._b[k]

    async def presign_get(self, k, expires_in=300):
        return f"http://fake/{k}"

    async def exists(self, k):
        return k in self._b


@pytest.fixture(autouse=True)
def _patch_age(monkeypatch, request):
    if "postgres_age_session" in request.fixturenames:
        return

    async def _noop(*a, **k):
        return None

    from sleuthgraph.entities import repository as ent_repo
    from sleuthgraph.relationships import repository as rel_repo

    monkeypatch.setattr(ent_repo, "upsert_vertex", _noop)
    monkeypatch.setattr(ent_repo, "delete_vertex", _noop)
    monkeypatch.setattr(rel_repo, "upsert_edge", _noop)
    monkeypatch.setattr(rel_repo, "delete_edge", _noop)


@pytest.fixture
async def sqlite_session_factory(test_engine):
    return async_sessionmaker(test_engine, expire_on_commit=False)


@pytest.fixture
async def seeded_case_and_entity(sqlite_session_factory):
    async with sqlite_session_factory() as s:
        u = User(
            id=uuid.uuid4(),
            email="t@x.com",
            hashed_password="x",
            is_active=True,
            is_superuser=False,
            is_verified=False,
        )
        s.add(u)
        await s.commit()
        case = Case(owner_id=u.id, name="T", tags=[])
        s.add(case)
        await s.commit()
        await s.refresh(case)
        ent = Entity(
            case_id=case.id,
            type=EntityType.DOMAIN.value,
            label="example.com",
            attrs={},
            confidence=1.0,
            created_by=u.id,
        )
        s.add(ent)
        await s.commit()
        await s.refresh(ent)
        return u.id, case.id, ent.id


@pytest.mark.asyncio
async def test_task_skips_if_not_queued(sqlite_session_factory, seeded_case_and_entity):
    user_id, case_id, ent_id = seeded_case_and_entity

    async with sqlite_session_factory() as s:
        run = PluginRun(
            case_id=case_id,
            input_entity_id=ent_id,
            plugin_name="stub_async",
            plugin_version="0.0.1",
            status="running",  # already running
            created_by=user_id,
        )
        s.add(run)
        await s.commit()
        run_id = str(run.id)

    ctx = {"session_factory": sqlite_session_factory}
    result = await run_plugin_task(ctx, run_id)
    assert result == {"status": "skipped", "reason": "not_queued"}


@pytest.mark.asyncio
async def test_task_not_found_returns_status(sqlite_session_factory):
    ctx = {"session_factory": sqlite_session_factory}
    result = await run_plugin_task(ctx, str(uuid.uuid4()))
    assert result == {"status": "not_found"}


@pytest.mark.asyncio
async def test_task_runs_plugin_and_marks_succeeded(sqlite_session_factory, seeded_case_and_entity):
    user_id, case_id, ent_id = seeded_case_and_entity

    async with sqlite_session_factory() as s:
        run = PluginRun(
            case_id=case_id,
            input_entity_id=ent_id,
            plugin_name="stub_async",
            plugin_version="0.0.1",
            status="queued",
            created_by=user_id,
        )
        s.add(run)
        await s.commit()
        run_id = str(run.id)

    registry = PluginRegistry([_StubPlugin()])
    storage = _FakeStorage()
    ctx = {
        "session_factory": sqlite_session_factory,
        "registry": registry,
        "storage": storage,
    }
    result = await run_plugin_task(ctx, run_id)
    assert result["status"] == "succeeded"
    assert result["entities"] == 1
    assert result["relationships"] == 1
    assert result["evidence"] == 1

    async with sqlite_session_factory() as s:
        reloaded = await s.get(PluginRun, uuid.UUID(run_id))
        assert reloaded is not None
        assert reloaded.status == "succeeded"
        assert reloaded.entities_created_count == 1


@pytest.mark.asyncio
async def test_task_fails_when_input_entity_missing(sqlite_session_factory, seeded_case_and_entity):
    user_id, case_id, _ent_id = seeded_case_and_entity

    async with sqlite_session_factory() as s:
        # Insert a run referencing a non-existent entity
        run = PluginRun(
            case_id=case_id,
            input_entity_id=uuid.uuid4(),  # not in DB
            plugin_name="stub_async",
            plugin_version="0.0.1",
            status="queued",
            created_by=user_id,
        )
        s.add(run)
        await s.commit()
        run_id = str(run.id)

    registry = PluginRegistry([_StubPlugin()])
    storage = _FakeStorage()
    ctx = {
        "session_factory": sqlite_session_factory,
        "registry": registry,
        "storage": storage,
    }
    result = await run_plugin_task(ctx, run_id)
    assert result == {"status": "failed", "reason": "missing_input_entity"}

    async with sqlite_session_factory() as s:
        reloaded = await s.get(PluginRun, uuid.UUID(run_id))
        assert reloaded is not None
        assert reloaded.status == "failed"
        assert reloaded.error_message == "missing_input_entity"
