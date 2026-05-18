"""EntityRepository: SQL + AGE atomic writes."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.cases.models import Case
from sleuthgraph.entities.repository import EntityRepository
from sleuthgraph.entities.schemas import EntityCreate, EntityUpdate
from sleuthgraph.entities.types import EntityType
from sleuthgraph.graph.age import GRAPH_NAME


@pytest.fixture
async def sqlite_db(test_engine):
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as s:
        yield s


@pytest.fixture
async def owner_case(sqlite_db):
    u = User(
        id=uuid.uuid4(),
        email="o@x.com",
        hashed_password="x",
        is_active=True,
        is_superuser=False,
        is_verified=False,
    )
    sqlite_db.add(u)
    await sqlite_db.commit()
    c = Case(owner_id=u.id, name="Test Case", tags=[])
    sqlite_db.add(c)
    await sqlite_db.commit()
    await sqlite_db.refresh(c)
    return u, c


# ---------- SQL-layer tests (no AGE -- sqlite won't run AGE) ----------
# For these we need the AGE call to be a no-op. We'll use a monkeypatched
# version of upsert_vertex/delete_vertex that's a no-op under sqlite.


@pytest.fixture(autouse=True)
def _patch_age_for_sqlite(request, monkeypatch):
    # Skip patching for tests that explicitly use postgres_age_session --
    # those tests restore the real functions themselves.
    if "postgres_age_session" in request.fixturenames:
        return

    async def _noop(*args, **kwargs):
        return None

    from sleuthgraph.entities import age as age_mod

    monkeypatch.setattr(age_mod, "upsert_vertex", _noop)
    monkeypatch.setattr(age_mod, "delete_vertex", _noop)
    # Also patch the names imported into repository.py module namespace
    from sleuthgraph.entities import repository as repo_mod

    monkeypatch.setattr(repo_mod, "upsert_vertex", _noop)
    monkeypatch.setattr(repo_mod, "delete_vertex", _noop)


@pytest.mark.asyncio
async def test_create_inserts_row(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    e = await repo.create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com"),
    )
    assert e.id is not None
    assert e.case_id == case.id
    assert e.type == "DOMAIN"
    assert e.label == "example.com"


@pytest.mark.asyncio
async def test_get_scoped_to_case(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    e = await repo.create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com"),
    )
    # Right case
    assert (await repo.get(e.id, case.id)) is not None
    # Wrong case
    assert (await repo.get(e.id, uuid.uuid4())) is None


@pytest.mark.asyncio
async def test_list_excludes_soft_deleted(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    e1 = await repo.create(case.id, None, EntityCreate(type=EntityType.DOMAIN, label="a.com"))
    e2 = await repo.create(case.id, None, EntityCreate(type=EntityType.DOMAIN, label="b.com"))
    await repo.soft_delete(e2.id, case.id)
    items = await repo.list_for_case(case.id)
    assert {x.id for x in items} == {e1.id}


@pytest.mark.asyncio
async def test_list_filters_by_type(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    d = await repo.create(case.id, None, EntityCreate(type=EntityType.DOMAIN, label="a.com"))
    _p = await repo.create(case.id, None, EntityCreate(type=EntityType.PERSON, label="Alice"))
    doms = await repo.list_for_case(case.id, entity_type="DOMAIN")
    assert {x.id for x in doms} == {d.id}


@pytest.mark.asyncio
async def test_update_partial(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    e = await repo.create(case.id, None, EntityCreate(type=EntityType.DOMAIN, label="a.com"))
    updated = await repo.update(e.id, case.id, EntityUpdate(confidence=0.5))
    assert updated.confidence == 0.5
    assert updated.label == "a.com"  # unchanged


@pytest.mark.asyncio
async def test_update_wrong_case_returns_none(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    e = await repo.create(case.id, None, EntityCreate(type=EntityType.DOMAIN, label="a.com"))
    assert (await repo.update(e.id, uuid.uuid4(), EntityUpdate(label="x"))) is None


@pytest.mark.asyncio
async def test_soft_delete_sets_deleted_at(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    e = await repo.create(case.id, None, EntityCreate(type=EntityType.DOMAIN, label="a.com"))
    assert (await repo.soft_delete(e.id, case.id)) is True
    assert (await repo.get(e.id, case.id)) is None


# ---------- Rollback tests: AGE failure must prevent SQL commit ----------


@pytest.mark.asyncio
async def test_create_rolls_back_sql_if_age_raises(sqlite_db, owner_case, monkeypatch):
    """If upsert_vertex raises, the entity row must NOT be persisted."""
    _, case = owner_case
    from sqlalchemy import select

    from sleuthgraph.entities import repository as repo_mod
    from sleuthgraph.entities.models import Entity

    async def _fail(*args, **kwargs):
        raise RuntimeError("AGE failure")

    monkeypatch.setattr(repo_mod, "upsert_vertex", _fail)

    repo = EntityRepository(sqlite_db)
    with pytest.raises(RuntimeError, match="AGE failure"):
        await repo.create(
            case.id,
            None,
            EntityCreate(type=EntityType.DOMAIN, label="should-not-persist.com"),
        )

    # Row must not exist after rollback
    result = await sqlite_db.execute(select(Entity).where(Entity.label == "should-not-persist.com"))
    assert result.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_soft_delete_rolls_back_sql_if_age_raises(sqlite_db, owner_case, monkeypatch):
    """If delete_vertex raises, deleted_at must NOT be committed."""
    _, case = owner_case
    from sqlalchemy import select

    from sleuthgraph.entities import repository as repo_mod
    from sleuthgraph.entities.models import Entity

    # Create entity first (AGE noop still active from autouse fixture)
    repo = EntityRepository(sqlite_db)
    e = await repo.create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="stay-alive.com"),
    )
    # Capture the id now before any potential session expiry
    saved_id = e.id

    async def _fail(*args, **kwargs):
        raise RuntimeError("AGE delete failure")

    monkeypatch.setattr(repo_mod, "delete_vertex", _fail)

    with pytest.raises(RuntimeError, match="AGE delete failure"):
        await repo.soft_delete(saved_id, case.id)

    # After rollback, row should still be alive (deleted_at is None)
    result = await sqlite_db.execute(
        select(Entity).where(
            Entity.id == saved_id,
            Entity.deleted_at.is_(None),
        )
    )
    assert result.scalar_one_or_none() is not None


# ---------- AGE integration tests (live postgres) ----------


async def _age_vertex_exists(session, entity_id):
    from sqlalchemy import text

    await session.execute(text('SET search_path = ag_catalog, "$user", public;'))
    r = await session.execute(
        text(
            f"SELECT * FROM cypher('{GRAPH_NAME}', $$ "
            f"MATCH (v {{id: '{entity_id}'}}) RETURN count(v) AS c "
            f"$$) AS (c agtype);"
        )
    )
    row = r.first()
    return int(str(row[0]).split("::")[0]) > 0


@pytest.mark.asyncio
async def test_create_writes_age_vertex(postgres_age_session):
    # _patch_age_for_sqlite is skipped for this test (guarded by fixturenames check)
    # so repo_mod.upsert_vertex is already the real function here.
    user_id = uuid.uuid4()
    case_id = uuid.uuid4()
    postgres_age_session.add(
        User(
            id=user_id,
            email=f"u-{user_id}@x.com",
            hashed_password="x",
            is_active=True,
            is_superuser=False,
            is_verified=False,
        )
    )
    postgres_age_session.add(Case(id=case_id, owner_id=user_id, name="T", tags=[]))
    await postgres_age_session.commit()

    repo = EntityRepository(postgres_age_session)
    e = await repo.create(
        case_id, user_id, EntityCreate(type=EntityType.DOMAIN, label="example.com")
    )
    saved_id = e.id
    assert await _age_vertex_exists(postgres_age_session, saved_id)

    # Cleanup: soft-delete removes the AGE vertex too
    await repo.soft_delete(saved_id, case_id)
    assert not await _age_vertex_exists(postgres_age_session, saved_id)


# ---------- get_or_create tests ----------


@pytest.mark.asyncio
async def test_get_or_create_creates_when_absent(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    e, created = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com"),
    )
    assert created is True
    assert e.type == "DOMAIN"
    assert e.label == "example.com"


@pytest.mark.asyncio
async def test_get_or_create_returns_existing(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    first, created1 = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com"),
    )
    second, created2 = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com"),
    )
    assert created1 is True
    assert created2 is False
    assert first.id == second.id


@pytest.mark.asyncio
async def test_get_or_create_bumps_confidence_upward(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    first, _ = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com", confidence=0.5),
    )
    assert first.confidence == 0.5

    second, created = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com", confidence=0.9),
    )
    assert created is False
    assert second.id == first.id
    assert second.confidence == 0.9


@pytest.mark.asyncio
async def test_get_or_create_does_not_lower_confidence(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    first, _ = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com", confidence=0.9),
    )
    assert first.confidence == 0.9

    second, _ = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com", confidence=0.3),
    )
    assert second.confidence == 0.9


@pytest.mark.asyncio
async def test_get_or_create_different_types_are_different_entities(sqlite_db, owner_case):
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    dom, _ = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example"),
    )
    per, created = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.PERSON, label="example"),
    )
    assert created is True
    assert dom.id != per.id


@pytest.mark.asyncio
async def test_get_or_create_ignores_soft_deleted(sqlite_db, owner_case):
    """If previously-existing entity was soft-deleted, creating again returns a NEW row."""
    _, case = owner_case
    repo = EntityRepository(sqlite_db)
    first, _ = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com"),
    )
    await repo.soft_delete(first.id, case.id)

    second, created = await repo.get_or_create(
        case.id,
        None,
        EntityCreate(type=EntityType.DOMAIN, label="example.com"),
    )
    assert created is True
    assert second.id != first.id
