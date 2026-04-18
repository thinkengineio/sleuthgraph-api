"""Ledger export endpoint: JSON + CSV."""

import csv
import io
import json
import uuid

import pytest
from httpx import AsyncClient


class _FakeStorage:
    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    async def put(self, key, data, content_type="application/octet-stream"):
        self._blobs[key] = data

    async def get(self, key):
        return self._blobs[key]

    async def presign_get(self, key, expires_in=300):
        return f"http://fake/{key}"

    async def exists(self, key):
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
async def signup_with_storage(signup_client):
    """Attach FakeStorage to the exported router's DI."""
    import sleuthgraph.main as main_module
    from sleuthgraph.evidence.deps import get_storage as _get_storage
    fake = _FakeStorage()
    main_module.app.dependency_overrides[_get_storage] = lambda: fake
    try:
        yield signup_client, fake
    finally:
        main_module.app.dependency_overrides.pop(_get_storage, None)


async def _login(client, email):
    await client.post(
        "/auth/register",
        json={"email": email, "password": "hunter222", "name": email.split("@")[0]},
    )
    await client.post(
        "/auth/login", data={"username": email, "password": "hunter222"},
    )


async def _create_case(client):
    r = await client.post("/cases", json={"name": "Export Case"})
    return r.json()["id"]


async def _seed_evidence_directly(session, case_id, n=3):
    """Insert n evidence rows by hitting the underlying repo — fewer moving parts than multipart POSTs."""
    from sleuthgraph.evidence.repository import EvidenceRepository
    from sleuthgraph.evidence.schemas import EvidenceCreate
    storage = _FakeStorage()
    repo = EvidenceRepository(session, storage)
    for i in range(n):
        await repo.create(
            uuid.UUID(case_id), None,
            EvidenceCreate(query=f"q{i}", source_plugin="manual"),
            f"body-{i}".encode(), "text/plain",
        )
    return storage


@pytest.mark.asyncio
async def test_export_requires_auth(client: AsyncClient):
    r = await client.get(f"/cases/{uuid.uuid4()}/evidence/export")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_export_json_empty(signup_with_storage):
    signup_client, _ = signup_with_storage
    await _login(signup_client, "j1@example.com")
    case_id = await _create_case(signup_client)

    r = await signup_client.get(f"/cases/{case_id}/evidence/export?format=json")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert body["case_id"] == case_id
    assert "exported_at" in body
    assert body["items"] == []


@pytest.mark.asyncio
async def test_export_json_with_items(signup_with_storage):
    """Seeding uses the upload path via multipart to keep DB + blob consistent."""
    signup_client, _ = signup_with_storage
    await _login(signup_client, "j2@example.com")
    case_id = await _create_case(signup_client)

    # Seed 3 via multipart upload if the 4.6 router is present; otherwise fall back.
    # To avoid depending on 4.6, seed directly via the repo by grabbing a session.
    # But we only have httpx here, so use multipart if possible.
    import io as _io
    for i in range(3):
        r = await signup_client.post(
            f"/cases/{case_id}/evidence",
            files={"file": ("x.txt", _io.BytesIO(f"body-{i}".encode()), "text/plain")},
            data={"metadata": json.dumps({"query": f"q{i}", "source_plugin": "manual"})},
        )
        # If 4.6 router isn't merged, this will 405 or 404 — skip the test
        if r.status_code in (404, 405):
            pytest.skip("Evidence POST router (Task 4.6) not on this branch; skipping seed")
        assert r.status_code == 201

    r = await signup_client.get(f"/cases/{case_id}/evidence/export")
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 3


@pytest.mark.asyncio
async def test_export_csv_empty(signup_with_storage):
    signup_client, _ = signup_with_storage
    await _login(signup_client, "c1@example.com")
    case_id = await _create_case(signup_client)

    r = await signup_client.get(f"/cases/{case_id}/evidence/export?format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    # Header row only
    reader = csv.reader(io.StringIO(r.text))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0] == [
        "id", "timestamp", "source_plugin", "query",
        "response_hash", "response_bytes", "response_content_type",
        "entity_id", "reproducibility_spec",
    ]
    # Content-Disposition attachment
    assert "attachment" in r.headers.get("content-disposition", "")


@pytest.mark.asyncio
async def test_export_rejects_invalid_format(signup_with_storage):
    signup_client, _ = signup_with_storage
    await _login(signup_client, "fmt@example.com")
    case_id = await _create_case(signup_client)

    r = await signup_client.get(f"/cases/{case_id}/evidence/export?format=xml")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_export_case_ownership_isolation(signup_with_storage):
    signup_client, _ = signup_with_storage
    await _login(signup_client, "u1ex@example.com")
    case_id = await _create_case(signup_client)

    await signup_client.post("/auth/logout")
    await _login(signup_client, "u2ex@example.com")

    r = await signup_client.get(f"/cases/{case_id}/evidence/export")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_csv_export_neutralizes_formula_injection(signup_with_storage):
    """A query starting with = gets a leading ' so Excel won't eval it."""
    signup_client, _ = signup_with_storage
    await _login(signup_client, "csvi@example.com")
    case_id = await _create_case(signup_client)

    # Seed via the upload route
    r = await signup_client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("a.bin", io.BytesIO(b"a"), "application/octet-stream")},
        data={"metadata": json.dumps({"query": "=CMD|'/c calc'!A1"})},
    )
    assert r.status_code == 201

    r = await signup_client.get(f"/cases/{case_id}/evidence/export?format=csv")
    assert r.status_code == 200

    # The injected formula should be quoted/neutralized
    lines = r.text.strip().split("\n")
    data_row = list(csv.reader([lines[1]]))[0]
    query_col = data_row[3]  # fourth column is 'query'
    assert query_col.startswith("'="), f"expected formula-neutralized cell, got: {query_col!r}"
