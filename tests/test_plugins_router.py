"""HTTP tests for /plugins + /cases/{id}/plugins/*."""

import uuid

import pytest
from httpx import AsyncClient

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


class _FakePlugin(OSINTPlugin):
    name = "fake"
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
async def signup_with_plugins(signup_client):
    from sleuthgraph.evidence.deps import get_storage

    app = signup_client._test_app  # type: ignore[attr-defined]
    fake_reg = PluginRegistry([_FakePlugin()])
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
async def test_list_plugins_requires_auth(client: AsyncClient):
    r = await client.get("/plugins")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_list_plugins_returns_registered(signup_with_plugins):
    signup_client, _, _ = signup_with_plugins
    await _login(signup_client, "p1@example.com")
    r = await signup_client.get("/plugins")
    assert r.status_code == 200
    body = r.json()
    assert any(p["name"] == "fake" for p in body)


@pytest.mark.asyncio
async def test_get_plugin_unknown_is_404(signup_with_plugins):
    signup_client, _, _ = signup_with_plugins
    await _login(signup_client, "p2@example.com")
    r = await signup_client.get("/plugins/nope")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_run_plugin_happy_path(signup_with_plugins):
    signup_client, _, _ = signup_with_plugins
    await _login(signup_client, "run1@example.com")
    case_id = await _new_case(signup_client)
    ent_id = await _new_entity(signup_client, case_id, "DOMAIN", "example.com")

    r = await signup_client.post(
        f"/cases/{case_id}/plugins/fake/run",
        json={"input_entity_id": ent_id},
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["run"]["status"] == "succeeded"
    assert body["run"]["entities_created_count"] == 1
    assert len(body["entities"]) == 1
    assert len(body["relationships"]) == 1
    assert len(body["evidence"]) == 1


@pytest.mark.asyncio
async def test_run_plugin_unknown_plugin_404(signup_with_plugins):
    signup_client, _, _ = signup_with_plugins
    await _login(signup_client, "run2@example.com")
    case_id = await _new_case(signup_client)
    ent_id = await _new_entity(signup_client, case_id, "DOMAIN", "example.com")
    r = await signup_client.post(
        f"/cases/{case_id}/plugins/nonexistent/run",
        json={"input_entity_id": ent_id},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_run_plugin_wrong_entity_type_422(signup_with_plugins):
    signup_client, _, _ = signup_with_plugins
    await _login(signup_client, "run3@example.com")
    case_id = await _new_case(signup_client)
    person = await _new_entity(signup_client, case_id, "PERSON", "Alice")
    r = await signup_client.post(
        f"/cases/{case_id}/plugins/fake/run",
        json={"input_entity_id": person},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_run_plugin_entity_not_in_case_404(signup_with_plugins):
    signup_client, _, _ = signup_with_plugins
    await _login(signup_client, "run4@example.com")
    case_id = await _new_case(signup_client)
    r = await signup_client.post(
        f"/cases/{case_id}/plugins/fake/run",
        json={"input_entity_id": str(uuid.uuid4())},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_case_ownership_isolation_on_run(signup_with_plugins):
    signup_client, _, _ = signup_with_plugins
    await _login(signup_client, "u1@example.com")
    case_id = await _new_case(signup_client)
    ent_id = await _new_entity(signup_client, case_id, "DOMAIN", "example.com")

    await signup_client.post("/auth/logout")
    await _login(signup_client, "u2@example.com")

    r = await signup_client.post(
        f"/cases/{case_id}/plugins/fake/run",
        json={"input_entity_id": ent_id},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_list_runs_empty(signup_with_plugins):
    signup_client, _, _ = signup_with_plugins
    await _login(signup_client, "rl@example.com")
    case_id = await _new_case(signup_client)
    r = await signup_client.get(f"/cases/{case_id}/plugins/runs")
    assert r.status_code == 200
    assert r.json()["total"] == 0


@pytest.mark.asyncio
async def test_list_runs_after_run(signup_with_plugins):
    signup_client, _, _ = signup_with_plugins
    await _login(signup_client, "rl2@example.com")
    case_id = await _new_case(signup_client)
    ent_id = await _new_entity(signup_client, case_id, "DOMAIN", "example.com")
    await signup_client.post(
        f"/cases/{case_id}/plugins/fake/run",
        json={"input_entity_id": ent_id},
    )
    r = await signup_client.get(f"/cases/{case_id}/plugins/runs")
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert body["items"][0]["status"] == "succeeded"
