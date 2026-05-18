"""HTTP tests for /cases/{case_id}/relationships CRUD (no update)."""

import uuid

import pytest
from httpx import AsyncClient

# Ensure FK-referenced tables are registered on Base.metadata before
# conftest.test_engine runs create_all.
import sleuthgraph.cases.models as _cases_models  # noqa: F401
import sleuthgraph.entities.models as _entities_models  # noqa: F401
import sleuthgraph.relationships.models as _rel_models  # noqa: F401


@pytest.fixture(autouse=True)
def _patch_age_for_sqlite(monkeypatch, request):
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


async def _register_and_login(client: AsyncClient, email: str):
    r = await client.post(
        "/auth/register",
        json={"email": email, "password": "hunter222hunt", "name": email.split("@")[0]},
    )
    assert r.status_code == 201
    r = await client.post(
        "/auth/login",
        data={"username": email, "password": "hunter222hunt"},
    )
    assert r.status_code in (200, 204)


async def _create_case(client: AsyncClient, name: str = "C1") -> str:
    r = await client.post("/cases", json={"name": name})
    assert r.status_code == 201
    return r.json()["id"]


async def _create_entity(client: AsyncClient, case_id: str, etype: str, label: str) -> str:
    r = await client.post(
        f"/cases/{case_id}/entities",
        json={"type": etype, "label": label},
    )
    assert r.status_code == 201
    return r.json()["id"]


@pytest.mark.asyncio
async def test_unauthed_is_401(client: AsyncClient):
    r = await client.post(
        f"/cases/{uuid.uuid4()}/relationships",
        json={
            "src_entity_id": str(uuid.uuid4()),
            "dst_entity_id": str(uuid.uuid4()),
            "rel_type": "RESOLVES_TO",
        },
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_create_list_get_delete(signup_client: AsyncClient):
    await _register_and_login(signup_client, "r-crud@example.com")
    case_id = await _create_case(signup_client)
    src = await _create_entity(signup_client, case_id, "DOMAIN", "src.com")
    dst = await _create_entity(signup_client, case_id, "IP_ADDRESS", "1.2.3.4")

    # CREATE
    r = await signup_client.post(
        f"/cases/{case_id}/relationships",
        json={
            "src_entity_id": src,
            "dst_entity_id": dst,
            "rel_type": "RESOLVES_TO",
            "confidence": 0.8,
        },
    )
    assert r.status_code == 201, r.text
    rel = r.json()
    rel_id = rel["id"]
    assert rel["rel_type"] == "RESOLVES_TO"
    assert rel["confidence"] == 0.8

    # GET
    r = await signup_client.get(f"/cases/{case_id}/relationships/{rel_id}")
    assert r.status_code == 200
    assert r.json()["id"] == rel_id

    # LIST
    r = await signup_client.get(f"/cases/{case_id}/relationships")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # LIST with rel_type filter
    r = await signup_client.get(
        f"/cases/{case_id}/relationships",
        params={"rel_type": "RESOLVES_TO"},
    )
    assert len(r.json()) == 1
    r = await signup_client.get(
        f"/cases/{case_id}/relationships",
        params={"rel_type": "OWNS"},
    )
    assert r.json() == []

    # LIST with src filter
    r = await signup_client.get(
        f"/cases/{case_id}/relationships",
        params={"src": src},
    )
    assert len(r.json()) == 1

    # DELETE
    r = await signup_client.delete(f"/cases/{case_id}/relationships/{rel_id}")
    assert r.status_code == 204

    # GET after delete → 404
    r = await signup_client.get(f"/cases/{case_id}/relationships/{rel_id}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_no_update_endpoint(signup_client: AsyncClient):
    await _register_and_login(signup_client, "r-noupdate@example.com")
    case_id = await _create_case(signup_client)
    # PATCH/PUT to a random rel id should return 405 (method not allowed) or 404
    r = await signup_client.patch(
        f"/cases/{case_id}/relationships/{uuid.uuid4()}",
        json={"confidence": 0.5},
    )
    assert r.status_code in (405, 404, 422)


@pytest.mark.asyncio
async def test_create_with_endpoint_not_in_case_returns_400(signup_client: AsyncClient):
    await _register_and_login(signup_client, "r-badend@example.com")
    case_a = await _create_case(signup_client, "A")
    case_b = await _create_case(signup_client, "B")
    src_a = await _create_entity(signup_client, case_a, "DOMAIN", "a.com")
    dst_a = await _create_entity(signup_client, case_a, "IP_ADDRESS", "1.1.1.1")

    # Try to create a relationship in case_b using case_a's entities → 400
    r = await signup_client.post(
        f"/cases/{case_b}/relationships",
        json={
            "src_entity_id": src_a,
            "dst_entity_id": dst_a,
            "rel_type": "RESOLVES_TO",
        },
    )
    assert r.status_code == 400, r.text


@pytest.mark.asyncio
async def test_case_ownership_isolation(signup_client: AsyncClient):
    # User 1 creates case + entities + relationship
    await _register_and_login(signup_client, "u1@example.com")
    case_id = await _create_case(signup_client)
    src = await _create_entity(signup_client, case_id, "DOMAIN", "a.com")
    dst = await _create_entity(signup_client, case_id, "IP_ADDRESS", "1.2.3.4")
    r = await signup_client.post(
        f"/cases/{case_id}/relationships",
        json={"src_entity_id": src, "dst_entity_id": dst, "rel_type": "RESOLVES_TO"},
    )
    rel_id = r.json()["id"]

    await signup_client.post("/auth/logout")

    # User 2 cannot see/modify anything
    await _register_and_login(signup_client, "u2@example.com")
    r = await signup_client.get(f"/cases/{case_id}/relationships/{rel_id}")
    assert r.status_code == 404
    r = await signup_client.get(f"/cases/{case_id}/relationships")
    assert r.status_code == 404
    r = await signup_client.delete(f"/cases/{case_id}/relationships/{rel_id}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_invalid_rel_type_is_422(signup_client: AsyncClient):
    await _register_and_login(signup_client, "u@example.com")
    case_id = await _create_case(signup_client)
    src = await _create_entity(signup_client, case_id, "DOMAIN", "a.com")
    dst = await _create_entity(signup_client, case_id, "IP_ADDRESS", "1.2.3.4")
    r = await signup_client.post(
        f"/cases/{case_id}/relationships",
        json={"src_entity_id": src, "dst_entity_id": dst, "rel_type": "GHOST_RELATION"},
    )
    assert r.status_code == 422
