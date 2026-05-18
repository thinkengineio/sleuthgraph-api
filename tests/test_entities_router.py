"""HTTP tests for /cases/{case_id}/entities CRUD with ownership isolation."""

import uuid

import pytest
from httpx import AsyncClient

# Ensure FK-referenced tables are registered on Base.metadata before
# conftest.test_engine runs create_all (mirrors pattern in test_entities_repository.py).
import sleuthgraph.cases.models as _cases_models  # noqa: F401
import sleuthgraph.entities.models as _entities_models  # noqa: F401


async def _register_and_login(client: AsyncClient, email: str, password: str = "hunter222hunt"):
    r = await client.post(
        "/auth/register",
        json={"email": email, "password": password, "name": email.split("@")[0]},
    )
    assert r.status_code == 201, r.text
    r = await client.post(
        "/auth/login",
        data={"username": email, "password": password},
    )
    assert r.status_code in (200, 204), r.text


async def _create_case(client: AsyncClient, name: str = "C1") -> str:
    r = await client.post("/cases", json={"name": name})
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.fixture(autouse=True)
def _patch_age_for_sqlite(monkeypatch, request):
    """Stub out AGE calls during sqlite-backed HTTP tests."""
    if "postgres_age_session" in request.fixturenames:
        return

    async def _noop(*a, **k):
        return None

    from sleuthgraph.entities import repository as repo_mod

    monkeypatch.setattr(repo_mod, "upsert_vertex", _noop)
    monkeypatch.setattr(repo_mod, "delete_vertex", _noop)


@pytest.mark.asyncio
async def test_unauthed_create_is_401(client: AsyncClient):
    r = await client.post(
        f"/cases/{uuid.uuid4()}/entities",
        json={"type": "DOMAIN", "label": "example.com"},
    )
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_create_list_get_update_delete_entity(signup_client: AsyncClient):
    await _register_and_login(signup_client, "e-crud@example.com")
    case_id = await _create_case(signup_client)

    # CREATE
    r = await signup_client.post(
        f"/cases/{case_id}/entities",
        json={"type": "DOMAIN", "label": "example.com", "attrs": {"registrar": "NC"}},
    )
    assert r.status_code == 201, r.text
    created = r.json()
    entity_id = created["id"]
    assert created["case_id"] == case_id
    assert created["type"] == "DOMAIN"
    assert created["label"] == "example.com"
    assert created["attrs"] == {"registrar": "NC"}
    assert created["confidence"] == 1.0

    # GET
    r = await signup_client.get(f"/cases/{case_id}/entities/{entity_id}")
    assert r.status_code == 200
    assert r.json()["id"] == entity_id

    # LIST
    r = await signup_client.get(f"/cases/{case_id}/entities")
    assert r.status_code == 200
    assert len(r.json()) == 1

    # LIST with type filter
    r = await signup_client.get(f"/cases/{case_id}/entities", params={"type": "DOMAIN"})
    assert r.status_code == 200
    assert len(r.json()) == 1
    r = await signup_client.get(f"/cases/{case_id}/entities", params={"type": "PERSON"})
    assert r.status_code == 200
    assert r.json() == []

    # PATCH
    r = await signup_client.patch(
        f"/cases/{case_id}/entities/{entity_id}",
        json={"confidence": 0.5},
    )
    assert r.status_code == 200
    assert r.json()["confidence"] == 0.5

    # DELETE
    r = await signup_client.delete(f"/cases/{case_id}/entities/{entity_id}")
    assert r.status_code == 204

    # GET after delete → 404
    r = await signup_client.get(f"/cases/{case_id}/entities/{entity_id}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_case_ownership_isolation(signup_client: AsyncClient):
    # User 1 creates case + entity
    await _register_and_login(signup_client, "u1@example.com")
    case_id = await _create_case(signup_client)
    r = await signup_client.post(
        f"/cases/{case_id}/entities",
        json={"type": "DOMAIN", "label": "example.com"},
    )
    entity_id = r.json()["id"]

    await signup_client.post("/auth/logout")

    # User 2 logs in; cannot access User 1's entity
    await _register_and_login(signup_client, "u2@example.com")

    # GET the case's entity → 404 (case ownership check fails first)
    r = await signup_client.get(f"/cases/{case_id}/entities/{entity_id}")
    assert r.status_code == 404

    # LIST entities in User 1's case → 404 (not empty list; we don't leak existence)
    r = await signup_client.get(f"/cases/{case_id}/entities")
    assert r.status_code == 404

    # POST to User 1's case → 404
    r = await signup_client.post(
        f"/cases/{case_id}/entities",
        json={"type": "DOMAIN", "label": "hijack.com"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_nonexistent_case_is_404(signup_client: AsyncClient):
    await _register_and_login(signup_client, "u@example.com")
    fake_case = uuid.uuid4()
    r = await signup_client.get(f"/cases/{fake_case}/entities")
    assert r.status_code == 404
    r = await signup_client.post(
        f"/cases/{fake_case}/entities",
        json={"type": "DOMAIN", "label": "x.com"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_invalid_entity_type_is_422(signup_client: AsyncClient):
    await _register_and_login(signup_client, "u@example.com")
    case_id = await _create_case(signup_client)
    r = await signup_client.post(
        f"/cases/{case_id}/entities",
        json={"type": "GHOST", "label": "x"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_entity_from_other_case_not_accessible(signup_client: AsyncClient):
    """Entity belongs to case A; querying case B's route with entity A's id → 404."""
    await _register_and_login(signup_client, "u@example.com")
    case_a = await _create_case(signup_client, "A")
    case_b = await _create_case(signup_client, "B")
    r = await signup_client.post(
        f"/cases/{case_a}/entities",
        json={"type": "DOMAIN", "label": "a.com"},
    )
    entity_a = r.json()["id"]

    # Access entity A via case B's route → 404
    r = await signup_client.get(f"/cases/{case_b}/entities/{entity_a}")
    assert r.status_code == 404
