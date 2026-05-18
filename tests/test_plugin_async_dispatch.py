"""Async dispatch path: dispatch_mode="async" → 202 + status=queued + enqueued job."""

from unittest.mock import AsyncMock, patch

import pytest

from sleuthgraph.entities.types import EntityType
from sleuthgraph.plugins.base import (
    EntityProposal,
    EvidenceProposal,
    OSINTPlugin,
    QueryResult,
    RelationshipProposal,
)
from sleuthgraph.plugins.deps import get_registry
from sleuthgraph.plugins.registry import PluginRegistry
from sleuthgraph.relationships.types import RelationshipType


class _AsyncStubPlugin(OSINTPlugin):
    name = "async_stub"
    version = "0.0.1"
    entity_types_accepted = [EntityType.DOMAIN]
    entity_types_produced = [EntityType.DOMAIN]
    requires_credentials = False
    dispatch_mode = "async"

    async def query(self, input_entity, credentials, context):
        return QueryResult()


class _SyncStubPlugin(OSINTPlugin):
    name = "sync_stub"
    version = "0.0.1"
    entity_types_accepted = [EntityType.DOMAIN]
    entity_types_produced = [EntityType.DOMAIN]
    requires_credentials = False
    # dispatch_mode left default = "sync"

    async def query(self, input_entity, credentials, context):
        return QueryResult(
            entities=[EntityProposal(ref="a", type=EntityType.DOMAIN, label="a.example.com")],
            relationships=[
                RelationshipProposal(
                    src={"ref": "a"},
                    dst={"input": True},
                    rel_type=RelationshipType.SUBDOMAIN_OF,
                )
            ],
            evidence=[EvidenceProposal(query="q", payload=b"{}", content_type="application/json")],
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
async def signup_with_async_plugin(signup_client):
    from sleuthgraph.evidence.deps import get_storage

    app = signup_client._test_app  # type: ignore[attr-defined]
    fake_reg = PluginRegistry([_AsyncStubPlugin(), _SyncStubPlugin()])
    fake_store = _FakeStorage()
    app.dependency_overrides[get_registry] = lambda: fake_reg
    app.dependency_overrides[get_storage] = lambda: fake_store
    try:
        yield signup_client, fake_reg, fake_store
    finally:
        app.dependency_overrides.pop(get_registry, None)
        app.dependency_overrides.pop(get_storage, None)


async def _login(client, email):
    await client.post(
        "/auth/register",
        json={"email": email, "password": "hunter222hunt", "name": email.split("@")[0]},
    )
    await client.post("/auth/login", data={"username": email, "password": "hunter222hunt"})


async def _new_case(client):
    r = await client.post("/cases", json={"name": "P"})
    return r.json()["id"]


async def _new_entity(client, case_id, type_, label):
    r = await client.post(
        f"/cases/{case_id}/entities",
        json={"type": type_, "label": label},
    )
    assert r.status_code == 201
    return r.json()["id"]


@pytest.mark.asyncio
async def test_async_plugin_returns_202_and_queued_run(signup_with_async_plugin):
    signup_client, _, _ = signup_with_async_plugin
    await _login(signup_client, "async1@example.com")
    case_id = await _new_case(signup_client)
    ent_id = await _new_entity(signup_client, case_id, "DOMAIN", "example.com")

    with patch(
        "sleuthgraph.queue.enqueue.enqueue_plugin_run",
        new=AsyncMock(return_value="job-id-1"),
    ):
        r = await signup_client.post(
            f"/cases/{case_id}/plugins/async_stub/run",
            json={"input_entity_id": ent_id},
        )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["run"]["status"] == "queued"
    assert body["entities"] == []
    assert body["relationships"] == []
    assert body["evidence"] == []


@pytest.mark.asyncio
async def test_sync_plugin_path_still_201(signup_with_async_plugin):
    signup_client, _, _ = signup_with_async_plugin
    await _login(signup_client, "sync1@example.com")
    case_id = await _new_case(signup_client)
    ent_id = await _new_entity(signup_client, case_id, "DOMAIN", "example.com")

    r = await signup_client.post(
        f"/cases/{case_id}/plugins/sync_stub/run",
        json={"input_entity_id": ent_id},
    )
    assert r.status_code == 201, r.text
    assert r.json()["run"]["status"] == "succeeded"


@pytest.mark.asyncio
async def test_async_plugin_enqueue_failure_marks_run_failed(signup_with_async_plugin):
    signup_client, _, _ = signup_with_async_plugin
    await _login(signup_client, "asyncfail@example.com")
    case_id = await _new_case(signup_client)
    ent_id = await _new_entity(signup_client, case_id, "DOMAIN", "example.com")

    with patch(
        "sleuthgraph.queue.enqueue.enqueue_plugin_run",
        new=AsyncMock(side_effect=RuntimeError("redis down")),
    ):
        r = await signup_client.post(
            f"/cases/{case_id}/plugins/async_stub/run",
            json={"input_entity_id": ent_id},
        )
    assert r.status_code == 503
