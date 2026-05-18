"""EvidenceRepository: create + get + list, rollback, append-only."""

import os
import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.cases.models import Case
from sleuthgraph.evidence.hashing import hash_bytes
from sleuthgraph.evidence.repository import EvidenceRepository
from sleuthgraph.evidence.schemas import EvidenceCreate
from sleuthgraph.evidence.storage import EvidenceStorage, build_key


class _FakeStorage:
    """In-memory storage for unit tests.

    Records put/get calls. put() can be toggled to raise via ``.fail = True``
    so we can test the rollback path.
    """
    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}
        self.fail = False
        self.put_calls: list[tuple[str, bytes, str]] = []

    async def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        if self.fail:
            raise RuntimeError("boom")
        self.put_calls.append((key, data, content_type))
        self._blobs[key] = data

    async def get(self, key: str) -> bytes:
        return self._blobs[key]

    async def presign_get(self, key: str, expires_in: int = 300) -> str:
        return f"http://fake/{key}?Expires={expires_in}"

    async def exists(self, key: str) -> bool:
        return key in self._blobs


@pytest.fixture
async def sqlite_db(test_engine):
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as s:
        yield s


@pytest.fixture
async def seeded(sqlite_db):
    u = User(id=uuid.uuid4(), email="o@x.com", hashed_password="x",
             is_active=True, is_superuser=False, is_verified=False)
    sqlite_db.add(u)
    await sqlite_db.commit()
    c = Case(owner_id=u.id, name="C", tags=[])
    sqlite_db.add(c)
    await sqlite_db.commit()
    await sqlite_db.refresh(c)
    return u, c


# --- unit tests with fake storage ---

@pytest.mark.asyncio
async def test_create_uploads_blob_and_inserts_row(sqlite_db, seeded):
    _, case = seeded
    storage = _FakeStorage()
    repo = EvidenceRepository(sqlite_db, storage)
    payload = b'{"a":1}'

    ev = await repo.create(
        case.id, None,
        EvidenceCreate(query="manual capture"),
        payload,
        content_type="application/json",
    )

    assert ev.case_id == case.id
    assert ev.source_plugin == "manual"
    assert ev.response_hash == hash_bytes(payload)
    assert ev.response_uri == build_key(str(case.id), ev.response_hash)
    assert ev.response_bytes == len(payload)
    assert ev.response_content_type == "application/json"

    # Verify blob was uploaded
    assert len(storage.put_calls) == 1
    key, data, ct = storage.put_calls[0]
    assert key == ev.response_uri
    assert data == payload
    assert ct == "application/json"


@pytest.mark.asyncio
async def test_create_default_content_type(sqlite_db, seeded):
    _, case = seeded
    storage = _FakeStorage()
    repo = EvidenceRepository(sqlite_db, storage)
    ev = await repo.create(
        case.id, None,
        EvidenceCreate(query="q"),
        b"raw bytes", content_type=None,
    )
    assert ev.response_content_type == "application/octet-stream"
    # Storage should have been called with the same fallback content-type
    assert storage.put_calls[0][2] == "application/octet-stream"


@pytest.mark.asyncio
async def test_create_rolls_back_sql_if_blob_upload_fails(sqlite_db, seeded):
    _, case = seeded
    # Snapshot case_id before the rollback expires the ORM object
    case_id = case.id
    storage = _FakeStorage()
    storage.fail = True
    repo = EvidenceRepository(sqlite_db, storage)

    with pytest.raises(RuntimeError, match="boom"):
        await repo.create(
            case_id, None,
            EvidenceCreate(query="fails"),
            b"payload", content_type=None,
        )

    # No evidence row should exist (SQL was rolled back)
    from sqlalchemy import select, func
    from sleuthgraph.evidence.models import Evidence
    r = await sqlite_db.execute(
        select(func.count()).select_from(Evidence).where(Evidence.case_id == case_id)
    )
    assert r.scalar_one() == 0


@pytest.mark.asyncio
async def test_get_scoped_to_case(sqlite_db, seeded):
    _, case = seeded
    storage = _FakeStorage()
    repo = EvidenceRepository(sqlite_db, storage)
    ev = await repo.create(
        case.id, None,
        EvidenceCreate(query="x"),
        b"payload", content_type=None,
    )
    assert (await repo.get(ev.id, case.id)) is not None
    assert (await repo.get(ev.id, uuid.uuid4())) is None


@pytest.mark.asyncio
async def test_list_returns_items_and_total(sqlite_db, seeded):
    _, case = seeded
    storage = _FakeStorage()
    repo = EvidenceRepository(sqlite_db, storage)
    for i in range(7):
        await repo.create(
            case.id, None,
            EvidenceCreate(query=f"q{i}"),
            f"payload-{i}".encode(), content_type=None,
        )
    items, total = await repo.list_for_case(case.id, limit=5, offset=0)
    assert len(items) == 5
    assert total == 7


@pytest.mark.asyncio
async def test_list_filter_by_source_plugin(sqlite_db, seeded):
    _, case = seeded
    storage = _FakeStorage()
    repo = EvidenceRepository(sqlite_db, storage)
    await repo.create(case.id, None, EvidenceCreate(query="manual-1"),
                       b"a", None)
    await repo.create(case.id, None,
                       EvidenceCreate(query="plugin-1", source_plugin="crt.sh@0.1.0"),
                       b"b", None)
    manual_items, manual_total = await repo.list_for_case(case.id, source_plugin="manual")
    assert manual_total == 1
    crt_items, crt_total = await repo.list_for_case(case.id, source_plugin="crt.sh@0.1.0")
    assert crt_total == 1


@pytest.mark.asyncio
async def test_repository_has_no_update_or_delete_methods(sqlite_db):
    """The interface is append-only by design."""
    storage = _FakeStorage()
    repo = EvidenceRepository(sqlite_db, storage)
    assert not hasattr(repo, "update")
    assert not hasattr(repo, "soft_delete")
    assert not hasattr(repo, "delete")


# --- integration test (MinIO-backed) ---

@pytest.fixture
async def live_storage():
    s = EvidenceStorage(
        endpoint=os.environ.get("SLEUTHGRAPH_TEST_S3_ENDPOINT", "http://localhost:9000"),
        access_key="sleuthgraph",
        secret_key="changeme_local_only",
        bucket=os.environ.get("SLEUTHGRAPH_TEST_S3_BUCKET", "evidence"),
    )
    try:
        await s.exists("__probe__")
    except Exception as e:
        pytest.skip(f"MinIO not reachable: {e}")
    return s


@pytest.mark.asyncio
async def test_create_uploads_to_real_minio(postgres_age_session, live_storage):
    # Need a case row first — use raw SQL to avoid dragging in the full ORM graph here
    from sleuthgraph.auth.models import User
    from sleuthgraph.cases.models import Case
    user_id = uuid.uuid4()
    case_id = uuid.uuid4()
    postgres_age_session.add(User(
        id=user_id, email=f"u-{user_id}@x.com", hashed_password="x",
        is_active=True, is_superuser=False, is_verified=False,
    ))
    postgres_age_session.add(Case(id=case_id, owner_id=user_id, name="live", tags=[]))
    await postgres_age_session.commit()

    repo = EvidenceRepository(postgres_age_session, live_storage)
    payload = b'{"live":"test"}'
    ev = await repo.create(
        case_id, user_id,
        EvidenceCreate(query="live upload"),
        payload, "application/json",
    )

    # Fetch the blob back from MinIO, verify it matches
    got = await live_storage.get(ev.response_uri)
    assert got == payload
    assert hash_bytes(got) == ev.response_hash
