"""HTTP tests for /cases/{case_id}/graph."""

import uuid

import pytest
from httpx import AsyncClient


@pytest.fixture(autouse=True)
def _patch_age_for_sqlite(monkeypatch, request):
    if "postgres_age_session" in request.fixturenames:
        return
    async def _noop(*a, **k): return None
    from sleuthgraph.entities import repository as ent_repo
    from sleuthgraph.relationships import repository as rel_repo
    monkeypatch.setattr(ent_repo, "upsert_vertex", _noop)
    monkeypatch.setattr(ent_repo, "delete_vertex", _noop)
    monkeypatch.setattr(rel_repo, "upsert_edge", _noop)
    monkeypatch.setattr(rel_repo, "delete_edge", _noop)


async def _login(client: AsyncClient, email: str):
    await client.post(
        "/auth/register",
        json={"email": email, "password": "hunter222", "name": email.split("@")[0]},
    )
    await client.post(
        "/auth/login", data={"username": email, "password": "hunter222"},
    )


async def _create_case(client):
    r = await client.post("/cases", json={"name": "G"})
    return r.json()["id"]


async def _create_entity(client, case_id, etype, label):
    r = await client.post(f"/cases/{case_id}/entities", json={"type": etype, "label": label})
    return r.json()["id"]


@pytest.mark.asyncio
async def test_unauthed_is_401(client: AsyncClient):
    r = await client.get(f"/cases/{uuid.uuid4()}/graph")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_empty_case_returns_empty_graph(signup_client: AsyncClient):
    await _login(signup_client, "g-empty@example.com")
    case_id = await _create_case(signup_client)
    r = await signup_client.get(f"/cases/{case_id}/graph")
    assert r.status_code == 200
    body = r.json()
    assert body == {"vertices": [], "edges": []}


@pytest.mark.asyncio
async def test_case_with_entities_and_relationships(signup_client: AsyncClient):
    await _login(signup_client, "g-full@example.com")
    case_id = await _create_case(signup_client)

    a = await _create_entity(signup_client, case_id, "DOMAIN", "a.example.com")
    b = await _create_entity(signup_client, case_id, "IP_ADDRESS", "1.2.3.4")
    c = await _create_entity(signup_client, case_id, "PERSON", "Alice")

    r = await signup_client.post(
        f"/cases/{case_id}/relationships",
        json={"src_entity_id": a, "dst_entity_id": b, "rel_type": "RESOLVES_TO"},
    )
    assert r.status_code == 201

    r = await signup_client.post(
        f"/cases/{case_id}/relationships",
        json={"src_entity_id": a, "dst_entity_id": c, "rel_type": "OWNS"},
    )
    assert r.status_code == 201

    r = await signup_client.get(f"/cases/{case_id}/graph")
    assert r.status_code == 200
    body = r.json()
    assert len(body["vertices"]) == 3
    assert len(body["edges"]) == 2

    # Verify vertex shape
    v_ids = {v["id"] for v in body["vertices"]}
    assert v_ids == {a, b, c}
    a_vertex = next(v for v in body["vertices"] if v["id"] == a)
    assert a_vertex["type"] == "DOMAIN"
    assert a_vertex["label"] == "a.example.com"

    # Verify edge shape
    e = body["edges"][0]
    assert {"id", "source", "target", "rel_type", "confidence", "source_plugin", "attrs"} == set(e.keys())


@pytest.mark.asyncio
async def test_graph_excludes_soft_deleted_entities(signup_client: AsyncClient):
    await _login(signup_client, "g-soft@example.com")
    case_id = await _create_case(signup_client)
    a = await _create_entity(signup_client, case_id, "DOMAIN", "a.com")
    b = await _create_entity(signup_client, case_id, "DOMAIN", "b.com")

    # Delete entity b
    r = await signup_client.delete(f"/cases/{case_id}/entities/{b}")
    assert r.status_code == 204

    r = await signup_client.get(f"/cases/{case_id}/graph")
    ids = {v["id"] for v in r.json()["vertices"]}
    assert ids == {a}


@pytest.mark.asyncio
async def test_graph_excludes_soft_deleted_relationships(signup_client: AsyncClient):
    await _login(signup_client, "g-srel@example.com")
    case_id = await _create_case(signup_client)
    a = await _create_entity(signup_client, case_id, "DOMAIN", "a.com")
    b = await _create_entity(signup_client, case_id, "IP_ADDRESS", "1.2.3.4")
    r = await signup_client.post(
        f"/cases/{case_id}/relationships",
        json={"src_entity_id": a, "dst_entity_id": b, "rel_type": "RESOLVES_TO"},
    )
    rel_id = r.json()["id"]

    # Delete the relationship
    await signup_client.delete(f"/cases/{case_id}/relationships/{rel_id}")

    r = await signup_client.get(f"/cases/{case_id}/graph")
    assert r.json()["edges"] == []
    assert len(r.json()["vertices"]) == 2  # entities survive


@pytest.mark.asyncio
async def test_case_not_owned_is_404(signup_client: AsyncClient):
    await _login(signup_client, "u1@example.com")
    case_id = await _create_case(signup_client)

    await signup_client.post("/auth/logout")
    await _login(signup_client, "u2@example.com")

    r = await signup_client.get(f"/cases/{case_id}/graph")
    assert r.status_code == 404
