"""HTTP tests for /cases/{case_id}/evidence."""

import io
import json
import uuid

import pytest
from httpx import AsyncClient


class _FakeStorage:
    """Shared with tests/test_evidence_repository.py — in-memory stand-in."""
    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    async def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self._blobs[key] = data

    async def get(self, key: str) -> bytes:
        return self._blobs[key]

    async def presign_get(self, key: str, expires_in: int = 300) -> str:
        return f"http://fake-minio/{key}?Expires={expires_in}"

    async def exists(self, key: str) -> bool:
        return key in self._blobs


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


@pytest.fixture
async def signup_client_with_fake_storage(signup_client):
    """Wrap signup_client so the evidence router uses FakeStorage."""
    import sleuthgraph.main as main_module
    from sleuthgraph.evidence.router import _get_storage
    fake = _FakeStorage()
    main_module.app.dependency_overrides[_get_storage] = lambda: fake
    try:
        yield signup_client, fake
    finally:
        main_module.app.dependency_overrides.pop(_get_storage, None)


async def _register_and_login(client: AsyncClient, email: str):
    await client.post(
        "/auth/register",
        json={"email": email, "password": "hunter222", "name": email.split("@")[0]},
    )
    await client.post(
        "/auth/login", data={"username": email, "password": "hunter222"},
    )


async def _create_case(client: AsyncClient, name: str = "C") -> str:
    r = await client.post("/cases", json={"name": name})
    return r.json()["id"]


@pytest.mark.asyncio
async def test_unauthed_is_401(client: AsyncClient):
    r = await client.get(f"/cases/{uuid.uuid4()}/evidence")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_post_list_get_blob_flow(signup_client_with_fake_storage):
    signup_client, storage = signup_client_with_fake_storage
    await _register_and_login(signup_client, "ev@example.com")
    case_id = await _create_case(signup_client)

    # POST evidence (multipart)
    metadata = json.dumps({"query": "captured from browser", "source_plugin": "manual"})
    files = {"file": ("capture.json", io.BytesIO(b'{"observed":"x"}'), "application/json")}
    data = {"metadata": metadata}
    r = await signup_client.post(
        f"/cases/{case_id}/evidence",
        files=files, data=data,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    ev_id = body["id"]
    assert body["source_plugin"] == "manual"
    assert body["response_bytes"] == len(b'{"observed":"x"}')
    assert body["response_content_type"] == "application/json"
    assert len(body["response_hash"]) == 64

    # Verify blob exists in fake storage
    assert await storage.exists(body["response_uri"])

    # LIST
    r = await signup_client.get(f"/cases/{case_id}/evidence")
    assert r.status_code == 200
    lst = r.json()
    assert lst["total"] == 1
    assert lst["limit"] == 50
    assert lst["offset"] == 0
    assert len(lst["items"]) == 1

    # GET one
    r = await signup_client.get(f"/cases/{case_id}/evidence/{ev_id}")
    assert r.status_code == 200
    assert r.json()["id"] == ev_id

    # GET blob — 307 redirect
    r = await signup_client.get(
        f"/cases/{case_id}/evidence/{ev_id}/blob",
        follow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["location"].startswith("http://fake-minio/")


@pytest.mark.asyncio
async def test_list_filter_by_source_plugin(signup_client_with_fake_storage):
    signup_client, _ = signup_client_with_fake_storage
    await _register_and_login(signup_client, "evf@example.com")
    case_id = await _create_case(signup_client)

    for plugin in ("manual", "manual", "crt.sh@0.1.0"):
        r = await signup_client.post(
            f"/cases/{case_id}/evidence",
            files={"file": ("x.bin", io.BytesIO(b"x"), "application/octet-stream")},
            data={"metadata": json.dumps({"query": "q", "source_plugin": plugin})},
        )
        assert r.status_code == 201

    r = await signup_client.get(
        f"/cases/{case_id}/evidence", params={"source_plugin": "manual"},
    )
    assert r.json()["total"] == 2
    r = await signup_client.get(
        f"/cases/{case_id}/evidence", params={"source_plugin": "crt.sh@0.1.0"},
    )
    assert r.json()["total"] == 1


@pytest.mark.asyncio
async def test_no_update_delete_endpoints(signup_client_with_fake_storage):
    """Attempt PUT/PATCH/DELETE => 405 Method Not Allowed."""
    signup_client, _ = signup_client_with_fake_storage
    await _register_and_login(signup_client, "evn@example.com")
    case_id = await _create_case(signup_client)
    # Upload one to have a valid id
    r = await signup_client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("a.bin", io.BytesIO(b"a"), "application/octet-stream")},
        data={"metadata": json.dumps({"query": "q"})},
    )
    ev_id = r.json()["id"]

    # PATCH
    r = await signup_client.patch(
        f"/cases/{case_id}/evidence/{ev_id}", json={"query": "new"},
    )
    assert r.status_code == 405

    # PUT
    r = await signup_client.put(
        f"/cases/{case_id}/evidence/{ev_id}", json={"query": "new"},
    )
    assert r.status_code == 405

    # DELETE
    r = await signup_client.delete(f"/cases/{case_id}/evidence/{ev_id}")
    assert r.status_code == 405


@pytest.mark.asyncio
async def test_case_ownership_isolation(signup_client_with_fake_storage):
    signup_client, _ = signup_client_with_fake_storage
    await _register_and_login(signup_client, "u1@example.com")
    case_id = await _create_case(signup_client)
    r = await signup_client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("a.bin", io.BytesIO(b"a"), "application/octet-stream")},
        data={"metadata": json.dumps({"query": "q"})},
    )
    ev_id = r.json()["id"]

    await signup_client.post("/auth/logout")
    await _register_and_login(signup_client, "u2@example.com")

    # All endpoints should return 404 (not 403, not empty list — no leak)
    r = await signup_client.get(f"/cases/{case_id}/evidence")
    assert r.status_code == 404
    r = await signup_client.get(f"/cases/{case_id}/evidence/{ev_id}")
    assert r.status_code == 404
    r = await signup_client.get(f"/cases/{case_id}/evidence/{ev_id}/blob")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_invalid_metadata_returns_422(signup_client_with_fake_storage):
    signup_client, _ = signup_client_with_fake_storage
    await _register_and_login(signup_client, "evm@example.com")
    case_id = await _create_case(signup_client)

    # Missing required field (query)
    r = await signup_client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("a.bin", io.BytesIO(b"a"), "application/octet-stream")},
        data={"metadata": json.dumps({"source_plugin": "manual"})},  # no query
    )
    assert r.status_code == 422
