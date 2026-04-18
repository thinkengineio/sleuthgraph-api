"""HTTP-level tests for /cases CRUD."""

import uuid

import pytest
from httpx import AsyncClient


async def _register_and_login(client: AsyncClient, email: str, password: str = "hunter222"):
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


@pytest.mark.asyncio
async def test_unauthed_request_is_401(client: AsyncClient):
    r = await client.post("/cases", json={"name": "Foo"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_create_list_get_update_delete(signup_client: AsyncClient):
    await _register_and_login(signup_client, "a@example.com")

    # CREATE
    r = await signup_client.post("/cases", json={"name": "Target Foo", "tags": ["ops"]})
    assert r.status_code == 201, r.text
    created = r.json()
    case_id = created["id"]
    assert created["name"] == "Target Foo"
    assert created["tags"] == ["ops"]
    assert created["status"] == "active"

    # GET
    r = await signup_client.get(f"/cases/{case_id}")
    assert r.status_code == 200
    assert r.json()["id"] == case_id

    # LIST
    r = await signup_client.get("/cases")
    assert r.status_code == 200
    items = r.json()
    assert len(items) == 1 and items[0]["id"] == case_id

    # PATCH
    r = await signup_client.patch(f"/cases/{case_id}", json={"status": "archived"})
    assert r.status_code == 200
    assert r.json()["status"] == "archived"

    # LIST with status filter
    r = await signup_client.get("/cases", params={"status": "archived"})
    assert r.status_code == 200
    assert len(r.json()) == 1

    r = await signup_client.get("/cases", params={"status": "active"})
    assert r.status_code == 200
    assert r.json() == []

    # DELETE
    r = await signup_client.delete(f"/cases/{case_id}")
    assert r.status_code == 204

    # GET after delete → 404
    r = await signup_client.get(f"/cases/{case_id}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_get_nonexistent_is_404(signup_client: AsyncClient):
    await _register_and_login(signup_client, "b@example.com")
    r = await signup_client.get(f"/cases/{uuid.uuid4()}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_ownership_isolation_between_users(signup_client: AsyncClient):
    # User 1 creates a case
    await _register_and_login(signup_client, "user1@example.com")
    r = await signup_client.post("/cases", json={"name": "User1 Case"})
    assert r.status_code == 201
    case_id = r.json()["id"]

    # User 1 logs out
    r = await signup_client.post("/auth/logout")
    assert r.status_code in (200, 204)

    # User 2 registers + logs in
    await _register_and_login(signup_client, "user2@example.com")

    # User 2 cannot see User 1's case (404, not 403 — no existence leak)
    r = await signup_client.get(f"/cases/{case_id}")
    assert r.status_code == 404

    # User 2's list is empty
    r = await signup_client.get("/cases")
    assert r.status_code == 200
    assert r.json() == []

    # User 2 cannot update or delete
    r = await signup_client.patch(f"/cases/{case_id}", json={"name": "hijack"})
    assert r.status_code == 404
    r = await signup_client.delete(f"/cases/{case_id}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_create_rejects_invalid_name(signup_client: AsyncClient):
    await _register_and_login(signup_client, "c@example.com")
    r = await signup_client.post("/cases", json={"name": ""})
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_pagination(signup_client: AsyncClient):
    await _register_and_login(signup_client, "d@example.com")
    for i in range(5):
        r = await signup_client.post("/cases", json={"name": f"C{i}"})
        assert r.status_code == 201

    r = await signup_client.get("/cases", params={"limit": 2, "offset": 0})
    assert r.status_code == 200
    page1 = r.json()
    assert len(page1) == 2

    r = await signup_client.get("/cases", params={"limit": 2, "offset": 2})
    page2 = r.json()
    assert len(page2) == 2
    assert not ({c["id"] for c in page1} & {c["id"] for c in page2})
