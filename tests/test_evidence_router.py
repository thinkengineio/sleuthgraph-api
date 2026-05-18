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

    async def put(
        self, key: str, data: bytes, content_type: str = "application/octet-stream"
    ) -> None:
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

    async def _noop(*a, **k):
        return None

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
    from sleuthgraph.evidence.deps import get_storage as _get_storage

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
        "/auth/login",
        data={"username": email, "password": "hunter222"},
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
        files=files,
        data=data,
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

    for plugin in ("manual", "manual", "crtsh"):
        r = await signup_client.post(
            f"/cases/{case_id}/evidence",
            files={"file": ("x.bin", io.BytesIO(b"x"), "application/octet-stream")},
            data={"metadata": json.dumps({"query": "q", "source_plugin": plugin})},
        )
        assert r.status_code == 201

    r = await signup_client.get(
        f"/cases/{case_id}/evidence",
        params={"source_plugin": "manual"},
    )
    assert r.json()["total"] == 2
    r = await signup_client.get(
        f"/cases/{case_id}/evidence",
        params={"source_plugin": "crtsh"},
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
        f"/cases/{case_id}/evidence/{ev_id}",
        json={"query": "new"},
    )
    assert r.status_code == 405

    # PUT
    r = await signup_client.put(
        f"/cases/{case_id}/evidence/{ev_id}",
        json={"query": "new"},
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


@pytest.mark.asyncio
async def test_upload_larger_than_max_returns_413(signup_client_with_fake_storage, monkeypatch):
    """Payloads over the configured cap are rejected with 413 before the body is buffered."""
    monkeypatch.setenv("EVIDENCE_MAX_UPLOAD_BYTES", "100")
    from sleuthgraph.config import get_settings

    get_settings.cache_clear()
    signup_client, _ = signup_client_with_fake_storage
    await _register_and_login(signup_client, "big@example.com")
    case_id = await _create_case(signup_client)

    oversized = b"x" * 200  # 2x the limit

    r = await signup_client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("big.bin", io.BytesIO(oversized), "application/octet-stream")},
        data={"metadata": json.dumps({"query": "big"})},
    )
    assert r.status_code == 413, r.text


@pytest.mark.asyncio
async def test_upload_at_limit_succeeds(signup_client_with_fake_storage, monkeypatch):
    """Payload exactly at the cap is accepted."""
    monkeypatch.setenv("EVIDENCE_MAX_UPLOAD_BYTES", "100")
    from sleuthgraph.config import get_settings

    get_settings.cache_clear()
    signup_client, _ = signup_client_with_fake_storage
    await _register_and_login(signup_client, "exact@example.com")
    case_id = await _create_case(signup_client)

    exactly_at_limit = b"x" * 100

    r = await signup_client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("ok.bin", io.BytesIO(exactly_at_limit), "application/octet-stream")},
        data={"metadata": json.dumps({"query": "ok"})},
    )
    assert r.status_code == 201


# ---------------------------------------------------------------------------
# Verify endpoint tests (#30)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_intact_evidence(signup_client_with_fake_storage):
    """POST /verify returns verified=true when blob matches stored hash."""
    signup_client, storage = signup_client_with_fake_storage
    await _register_and_login(signup_client, "verify-ok@example.com")
    case_id = await _create_case(signup_client)

    payload = b'{"observed":"y"}'
    metadata = json.dumps({"query": "test-verify", "source_plugin": "manual"})
    r = await signup_client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("v.json", io.BytesIO(payload), "application/json")},
        data={"metadata": metadata},
    )
    assert r.status_code == 201
    ev_id = r.json()["id"]

    r = await signup_client.post(f"/cases/{case_id}/evidence/{ev_id}/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is True
    assert body["expected"] == body["actual"]


@pytest.mark.asyncio
async def test_verify_tampered_evidence(signup_client_with_fake_storage):
    """POST /verify returns verified=false when blob has been tampered with."""
    signup_client, storage = signup_client_with_fake_storage
    await _register_and_login(signup_client, "verify-bad@example.com")
    case_id = await _create_case(signup_client)

    payload = b"original-content"
    metadata = json.dumps({"query": "test-tamper", "source_plugin": "manual"})
    r = await signup_client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("t.bin", io.BytesIO(payload), "application/octet-stream")},
        data={"metadata": metadata},
    )
    assert r.status_code == 201
    body = r.json()
    ev_id = body["id"]
    response_uri = body["response_uri"]

    # Tamper with the blob in fake storage
    storage._blobs[response_uri] = b"tampered-content"

    r = await signup_client.post(f"/cases/{case_id}/evidence/{ev_id}/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is False
    assert body["expected"] != body["actual"]


@pytest.mark.asyncio
async def test_verify_other_users_evidence_returns_404(signup_client_with_fake_storage):
    """Verify endpoint enforces case ownership — other user gets 404."""
    signup_client, _ = signup_client_with_fake_storage
    await _register_and_login(signup_client, "vown1@example.com")
    case_id = await _create_case(signup_client)

    r = await signup_client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("a.bin", io.BytesIO(b"a"), "application/octet-stream")},
        data={"metadata": json.dumps({"query": "q"})},
    )
    ev_id = r.json()["id"]

    await signup_client.post("/auth/logout")
    await _register_and_login(signup_client, "vown2@example.com")

    r = await signup_client.post(f"/cases/{case_id}/evidence/{ev_id}/verify")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_verify_nonexistent_evidence_returns_404(signup_client_with_fake_storage):
    """Verify against a bogus ev_id returns 404."""
    signup_client, _ = signup_client_with_fake_storage
    await _register_and_login(signup_client, "vnone@example.com")
    case_id = await _create_case(signup_client)

    r = await signup_client.post(
        f"/cases/{case_id}/evidence/{uuid.uuid4()}/verify",
    )
    assert r.status_code == 404
