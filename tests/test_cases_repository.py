"""CaseRepository CRUD + ownership + soft-delete."""

import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.cases.repository import CaseRepository
from sleuthgraph.cases.schemas import CaseCreate, CaseUpdate


@pytest.fixture
async def db(test_engine):
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as s:
        yield s


@pytest.fixture
async def owner(db):
    u = User(
        id=uuid.uuid4(), email="owner@example.com", hashed_password="x",
        is_active=True, is_superuser=False, is_verified=False,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


@pytest.fixture
async def other_owner(db):
    u = User(
        id=uuid.uuid4(), email="other@example.com", hashed_password="x",
        is_active=True, is_superuser=False, is_verified=False,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return u


@pytest.mark.asyncio
async def test_create_assigns_owner_and_defaults(db, owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Foo"))
    assert c.owner_id == owner.id
    assert c.name == "Foo"
    assert c.status == "active"
    assert c.tags == []
    assert c.deleted_at is None


@pytest.mark.asyncio
async def test_create_with_tags(db, owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Bar", tags=["a", "b"]))
    assert c.tags == ["a", "b"]


@pytest.mark.asyncio
async def test_get_returns_owned_case(db, owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Foo"))
    fetched = await repo.get(c.id, owner.id)
    assert fetched is not None
    assert fetched.id == c.id


@pytest.mark.asyncio
async def test_get_returns_none_for_wrong_owner(db, owner, other_owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Foo"))
    assert await repo.get(c.id, other_owner.id) is None


@pytest.mark.asyncio
async def test_get_returns_none_for_soft_deleted(db, owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Foo"))
    await repo.soft_delete(c.id, owner.id)
    assert await repo.get(c.id, owner.id) is None


@pytest.mark.asyncio
async def test_list_returns_owner_cases_only(db, owner, other_owner):
    repo = CaseRepository(db)
    c1 = await repo.create(owner.id, CaseCreate(name="A"))
    await repo.create(owner.id, CaseCreate(name="B"))
    await repo.create(other_owner.id, CaseCreate(name="Other"))

    items = await repo.list_for_owner(owner.id)
    assert len(items) == 2
    assert all(c.owner_id == owner.id for c in items)


@pytest.mark.asyncio
async def test_list_excludes_soft_deleted(db, owner):
    repo = CaseRepository(db)
    c1 = await repo.create(owner.id, CaseCreate(name="A"))
    c2 = await repo.create(owner.id, CaseCreate(name="B"))
    await repo.soft_delete(c2.id, owner.id)

    items = await repo.list_for_owner(owner.id)
    assert {c.id for c in items} == {c1.id}


@pytest.mark.asyncio
async def test_list_filters_by_status(db, owner):
    repo = CaseRepository(db)
    c1 = await repo.create(owner.id, CaseCreate(name="A"))
    c2 = await repo.create(owner.id, CaseCreate(name="B"))
    await repo.update(c2.id, owner.id, CaseUpdate(status="archived"))

    active = await repo.list_for_owner(owner.id, status="active")
    archived = await repo.list_for_owner(owner.id, status="archived")
    assert {c.id for c in active} == {c1.id}
    assert {c.id for c in archived} == {c2.id}


@pytest.mark.asyncio
async def test_list_pagination(db, owner):
    repo = CaseRepository(db)
    ids = []
    for i in range(5):
        c = await repo.create(owner.id, CaseCreate(name=f"C{i}"))
        ids.append(c.id)

    page1 = await repo.list_for_owner(owner.id, limit=2, offset=0)
    page2 = await repo.list_for_owner(owner.id, limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) == 2
    # No overlap
    assert not ({c.id for c in page1} & {c.id for c in page2})


@pytest.mark.asyncio
async def test_update_renames(db, owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Foo"))
    updated = await repo.update(c.id, owner.id, CaseUpdate(name="Bar"))
    assert updated is not None
    assert updated.name == "Bar"
    assert updated.status == "active"  # unchanged


@pytest.mark.asyncio
async def test_update_partial_preserves_unset_fields(db, owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Foo", tags=["x"]))
    updated = await repo.update(c.id, owner.id, CaseUpdate(status="archived"))
    assert updated.status == "archived"
    assert updated.name == "Foo"  # unchanged
    assert updated.tags == ["x"]  # unchanged


@pytest.mark.asyncio
async def test_update_wrong_owner_returns_none(db, owner, other_owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Foo"))
    assert await repo.update(c.id, other_owner.id, CaseUpdate(name="X")) is None


@pytest.mark.asyncio
async def test_soft_delete_sets_deleted_at(db, owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Foo"))
    ok = await repo.soft_delete(c.id, owner.id)
    assert ok is True


@pytest.mark.asyncio
async def test_soft_delete_wrong_owner_returns_false(db, owner, other_owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Foo"))
    assert await repo.soft_delete(c.id, other_owner.id) is False


@pytest.mark.asyncio
async def test_soft_delete_already_deleted_returns_false(db, owner):
    repo = CaseRepository(db)
    c = await repo.create(owner.id, CaseCreate(name="Foo"))
    await repo.soft_delete(c.id, owner.id)
    assert await repo.soft_delete(c.id, owner.id) is False
