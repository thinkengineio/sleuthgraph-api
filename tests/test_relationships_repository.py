"""RelationshipRepository CRUD + endpoint validation + AGE mirror.

Sqlite tests stub out upsert_edge / delete_edge via the _patch_age_for_sqlite
autouse fixture. Postgres-only tests are guarded by the postgres_age_session
fixture (auto-skipped if no live db).
"""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from sleuthgraph.auth.models import User
from sleuthgraph.cases.models import Case
from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.relationships.repository import (
    EndpointNotInCaseError,
    RelationshipRepository,
)
from sleuthgraph.relationships.schemas import RelationshipCreate
from sleuthgraph.relationships.types import RelationshipType

# ---------------------------------------------------------------------------
# AGE stub — skip when running against real postgres
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _patch_age_for_sqlite(request):
    """Stub out AGE helpers so sqlite-backed tests don't need a live graph.

    When the postgres_age_session fixture is active the stubs are NOT applied
    so the integration tests run against the real AGE extension.
    """
    if "postgres_age_session" in request.fixturenames:
        yield
        return

    with (
        patch(
            "sleuthgraph.relationships.repository.upsert_edge",
            new_callable=AsyncMock,
        ) as _upsert,
        patch(
            "sleuthgraph.relationships.repository.delete_edge",
            new_callable=AsyncMock,
        ) as _delete,
    ):
        yield {"upsert_edge": _upsert, "delete_edge": _delete}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def db(test_engine):
    TestSession = async_sessionmaker(test_engine, expire_on_commit=False)
    async with TestSession() as s:
        yield s


async def _make_user(db, email=None) -> User:
    u = User(
        id=uuid.uuid4(),
        email=email or f"user-{uuid.uuid4()}@example.com",
        hashed_password="x",
        is_active=True,
        is_superuser=False,
        is_verified=False,
    )
    db.add(u)
    await db.flush()
    return u


async def _make_case(db, owner_id: uuid.UUID) -> Case:
    c = Case(id=uuid.uuid4(), owner_id=owner_id, name="test-case", tags=[])
    db.add(c)
    await db.flush()
    return c


async def _make_entity(
    db, case_id: uuid.UUID, created_by: uuid.UUID, label: str = "example.com"
) -> Entity:
    now = datetime.now(UTC)
    e = Entity(
        id=uuid.uuid4(),
        case_id=case_id,
        type=EntityType.DOMAIN.value,
        label=label,
        attrs={},
        confidence=1.0,
        created_by=created_by,
        created_at=now,
        updated_at=now,
    )
    db.add(e)
    await db.flush()
    return e


# ---------------------------------------------------------------------------
# Basic CRUD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_and_get(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    src = await _make_entity(db, case.id, user.id, "src.example")
    dst = await _make_entity(db, case.id, user.id, "dst.example")
    await db.commit()

    repo = RelationshipRepository(db)
    data = RelationshipCreate(
        src_entity_id=src.id,
        dst_entity_id=dst.id,
        rel_type=RelationshipType.RESOLVES_TO,
        confidence=0.9,
        source_plugin="test-plugin",
        attrs={"note": "hi"},
    )
    rel = await repo.create(case.id, user.id, data)

    assert rel.id is not None
    assert rel.case_id == case.id
    assert rel.src_entity_id == src.id
    assert rel.dst_entity_id == dst.id
    assert rel.rel_type == RelationshipType.RESOLVES_TO.value
    assert rel.confidence == 0.9
    assert rel.source_plugin == "test-plugin"
    assert rel.attrs == {"note": "hi"}
    assert rel.created_by == user.id
    assert rel.deleted_at is None

    fetched = await repo.get(rel.id, case.id)
    assert fetched is not None
    assert fetched.id == rel.id


@pytest.mark.asyncio
async def test_get_returns_none_for_wrong_case(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    other_case = await _make_case(db, user.id)
    src = await _make_entity(db, case.id, user.id, "src.example")
    dst = await _make_entity(db, case.id, user.id, "dst.example")
    await db.commit()

    repo = RelationshipRepository(db)
    data = RelationshipCreate(
        src_entity_id=src.id,
        dst_entity_id=dst.id,
        rel_type=RelationshipType.OWNS,
    )
    rel = await repo.create(case.id, user.id, data)

    # Searching with other_case.id should return None
    assert await repo.get(rel.id, other_case.id) is None


@pytest.mark.asyncio
async def test_get_returns_none_after_soft_delete(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    src = await _make_entity(db, case.id, user.id, "src.example")
    dst = await _make_entity(db, case.id, user.id, "dst.example")
    await db.commit()

    repo = RelationshipRepository(db)
    data = RelationshipCreate(
        src_entity_id=src.id,
        dst_entity_id=dst.id,
        rel_type=RelationshipType.OWNS,
    )
    rel = await repo.create(case.id, user.id, data)
    await repo.soft_delete(rel.id, case.id)

    assert await repo.get(rel.id, case.id) is None


# ---------------------------------------------------------------------------
# list_for_case filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_for_case_returns_all(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    e1 = await _make_entity(db, case.id, user.id, "e1.example")
    e2 = await _make_entity(db, case.id, user.id, "e2.example")
    e3 = await _make_entity(db, case.id, user.id, "e3.example")
    await db.commit()

    repo = RelationshipRepository(db)
    await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.OWNS,
        ),
    )
    await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e2.id,
            dst_entity_id=e3.id,
            rel_type=RelationshipType.RESOLVES_TO,
        ),
    )

    items = await repo.list_for_case(case.id)
    assert len(items) == 2


@pytest.mark.asyncio
async def test_list_excludes_soft_deleted(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    e1 = await _make_entity(db, case.id, user.id, "e1.example")
    e2 = await _make_entity(db, case.id, user.id, "e2.example")
    e3 = await _make_entity(db, case.id, user.id, "e3.example")
    await db.commit()

    repo = RelationshipRepository(db)
    r1 = await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.OWNS,
        ),
    )
    await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e2.id,
            dst_entity_id=e3.id,
            rel_type=RelationshipType.RESOLVES_TO,
        ),
    )
    await repo.soft_delete(r1.id, case.id)

    items = await repo.list_for_case(case.id)
    assert len(items) == 1
    assert items[0].rel_type == RelationshipType.RESOLVES_TO.value


@pytest.mark.asyncio
async def test_list_filters_by_rel_type(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    e1 = await _make_entity(db, case.id, user.id, "e1.example")
    e2 = await _make_entity(db, case.id, user.id, "e2.example")
    e3 = await _make_entity(db, case.id, user.id, "e3.example")
    await db.commit()

    repo = RelationshipRepository(db)
    await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.OWNS,
        ),
    )
    await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e2.id,
            dst_entity_id=e3.id,
            rel_type=RelationshipType.RESOLVES_TO,
        ),
    )

    owns = await repo.list_for_case(case.id, rel_type="OWNS")
    resolves = await repo.list_for_case(case.id, rel_type="RESOLVES_TO")
    assert len(owns) == 1
    assert len(resolves) == 1


@pytest.mark.asyncio
async def test_list_filters_by_src(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    e1 = await _make_entity(db, case.id, user.id, "e1.example")
    e2 = await _make_entity(db, case.id, user.id, "e2.example")
    e3 = await _make_entity(db, case.id, user.id, "e3.example")
    await db.commit()

    repo = RelationshipRepository(db)
    await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.OWNS,
        ),
    )
    await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e2.id,
            dst_entity_id=e3.id,
            rel_type=RelationshipType.OWNS,
        ),
    )

    from_e1 = await repo.list_for_case(case.id, src=e1.id)
    assert len(from_e1) == 1
    assert from_e1[0].src_entity_id == e1.id


@pytest.mark.asyncio
async def test_list_filters_by_dst(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    e1 = await _make_entity(db, case.id, user.id, "e1.example")
    e2 = await _make_entity(db, case.id, user.id, "e2.example")
    e3 = await _make_entity(db, case.id, user.id, "e3.example")
    await db.commit()

    repo = RelationshipRepository(db)
    await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e3.id,
            rel_type=RelationshipType.OWNS,
        ),
    )
    await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e2.id,
            dst_entity_id=e3.id,
            rel_type=RelationshipType.OWNS,
        ),
    )

    to_e3 = await repo.list_for_case(case.id, dst=e3.id)
    assert len(to_e3) == 2
    assert all(r.dst_entity_id == e3.id for r in to_e3)


# ---------------------------------------------------------------------------
# soft_delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_soft_delete_returns_true(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    src = await _make_entity(db, case.id, user.id, "src.example")
    dst = await _make_entity(db, case.id, user.id, "dst.example")
    await db.commit()

    repo = RelationshipRepository(db)
    rel = await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=src.id,
            dst_entity_id=dst.id,
            rel_type=RelationshipType.OWNS,
        ),
    )
    assert await repo.soft_delete(rel.id, case.id) is True


@pytest.mark.asyncio
async def test_soft_delete_returns_false_for_wrong_case(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    other_case = await _make_case(db, user.id)
    src = await _make_entity(db, case.id, user.id, "src.example")
    dst = await _make_entity(db, case.id, user.id, "dst.example")
    await db.commit()

    repo = RelationshipRepository(db)
    rel = await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=src.id,
            dst_entity_id=dst.id,
            rel_type=RelationshipType.OWNS,
        ),
    )

    # Wrong case_id — must return False
    assert await repo.soft_delete(rel.id, other_case.id) is False


@pytest.mark.asyncio
async def test_soft_delete_already_deleted_returns_false(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    src = await _make_entity(db, case.id, user.id, "src.example")
    dst = await _make_entity(db, case.id, user.id, "dst.example")
    await db.commit()

    repo = RelationshipRepository(db)
    rel = await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=src.id,
            dst_entity_id=dst.id,
            rel_type=RelationshipType.OWNS,
        ),
    )
    await repo.soft_delete(rel.id, case.id)
    assert await repo.soft_delete(rel.id, case.id) is False


# ---------------------------------------------------------------------------
# Endpoint validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_fails_when_src_not_in_case(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    other_case = await _make_case(db, user.id)
    # src entity belongs to a different case
    src = await _make_entity(db, other_case.id, user.id, "foreign-src.example")
    dst = await _make_entity(db, case.id, user.id, "dst.example")
    await db.commit()

    repo = RelationshipRepository(db)
    with pytest.raises(EndpointNotInCaseError):
        await repo.create(
            case.id,
            user.id,
            RelationshipCreate(
                src_entity_id=src.id,
                dst_entity_id=dst.id,
                rel_type=RelationshipType.OWNS,
            ),
        )


@pytest.mark.asyncio
async def test_create_fails_when_dst_not_in_case(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    other_case = await _make_case(db, user.id)
    src = await _make_entity(db, case.id, user.id, "src.example")
    # dst entity belongs to a different case
    dst = await _make_entity(db, other_case.id, user.id, "foreign-dst.example")
    await db.commit()

    repo = RelationshipRepository(db)
    with pytest.raises(EndpointNotInCaseError):
        await repo.create(
            case.id,
            user.id,
            RelationshipCreate(
                src_entity_id=src.id,
                dst_entity_id=dst.id,
                rel_type=RelationshipType.OWNS,
            ),
        )


@pytest.mark.asyncio
async def test_create_fails_when_neither_endpoint_in_case(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    other_case = await _make_case(db, user.id)
    src = await _make_entity(db, other_case.id, user.id, "src.example")
    dst = await _make_entity(db, other_case.id, user.id, "dst.example")
    await db.commit()

    repo = RelationshipRepository(db)
    with pytest.raises(EndpointNotInCaseError):
        await repo.create(
            case.id,
            user.id,
            RelationshipCreate(
                src_entity_id=src.id,
                dst_entity_id=dst.id,
                rel_type=RelationshipType.OWNS,
            ),
        )


@pytest.mark.asyncio
async def test_self_loop_allowed(db):
    """ASSOCIATED_WITH can legally have src == dst."""
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    entity = await _make_entity(db, case.id, user.id, "self.example")
    await db.commit()

    repo = RelationshipRepository(db)
    rel = await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=entity.id,
            dst_entity_id=entity.id,
            rel_type=RelationshipType.ASSOCIATED_WITH,
        ),
    )
    assert rel.src_entity_id == rel.dst_entity_id == entity.id


# ---------------------------------------------------------------------------
# Postgres + AGE integration (auto-skipped without live db)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_writes_age_edge(postgres_age_session):
    """create() calls upsert_edge and the edge is visible in AGE."""
    from sqlalchemy import text

    from sleuthgraph.graph.age import GRAPH_NAME

    session = postgres_age_session
    user = await _make_user(session)
    case = await _make_case(session, user.id)

    # Need AGE vertices for both endpoints
    from sleuthgraph.entities.age import upsert_vertex

    now = datetime.now(UTC)
    e1 = Entity(
        id=uuid.uuid4(),
        case_id=case.id,
        type=EntityType.DOMAIN.value,
        label="age-src.example",
        attrs={},
        confidence=1.0,
        created_by=user.id,
        created_at=now,
        updated_at=now,
    )
    e2 = Entity(
        id=uuid.uuid4(),
        case_id=case.id,
        type=EntityType.IP_ADDRESS.value,
        label="10.0.0.1",
        attrs={},
        confidence=1.0,
        created_by=user.id,
        created_at=now,
        updated_at=now,
    )
    session.add_all([e1, e2])
    await session.flush()
    await upsert_vertex(session, e1)
    await upsert_vertex(session, e2)
    await session.commit()

    repo = RelationshipRepository(session)
    rel = await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.RESOLVES_TO,
        ),
    )

    # Verify the AGE edge was created
    await session.execute(text('SET search_path = ag_catalog, "$user", public;'))
    r = await session.execute(
        text(
            f"SELECT * FROM cypher('{GRAPH_NAME}', $$ "
            f"MATCH ()-[r {{id: '{rel.id}'}}]->() RETURN count(r) AS c "
            f"$$) AS (c agtype);"
        )
    )
    count = int(str(r.first()[0]).split("::")[0])
    assert count == 1

    # Cleanup
    from sleuthgraph.entities.age import delete_vertex
    from sleuthgraph.relationships.age import delete_edge

    await delete_edge(session, rel.id)
    await delete_vertex(session, e1.id)
    await delete_vertex(session, e2.id)
    await session.commit()


@pytest.mark.asyncio
async def test_soft_delete_removes_age_edge(postgres_age_session):
    """soft_delete() calls delete_edge and the edge disappears from AGE."""
    from sqlalchemy import text

    from sleuthgraph.entities.age import delete_vertex, upsert_vertex
    from sleuthgraph.graph.age import GRAPH_NAME

    session = postgres_age_session
    user = await _make_user(session)
    case = await _make_case(session, user.id)

    now = datetime.now(UTC)
    e1 = Entity(
        id=uuid.uuid4(),
        case_id=case.id,
        type=EntityType.DOMAIN.value,
        label="del-src.example",
        attrs={},
        confidence=1.0,
        created_by=user.id,
        created_at=now,
        updated_at=now,
    )
    e2 = Entity(
        id=uuid.uuid4(),
        case_id=case.id,
        type=EntityType.IP_ADDRESS.value,
        label="10.0.0.2",
        attrs={},
        confidence=1.0,
        created_by=user.id,
        created_at=now,
        updated_at=now,
    )
    session.add_all([e1, e2])
    await session.flush()
    await upsert_vertex(session, e1)
    await upsert_vertex(session, e2)
    await session.commit()

    repo = RelationshipRepository(session)
    rel = await repo.create(
        case.id,
        user.id,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.RESOLVES_TO,
        ),
    )

    await repo.soft_delete(rel.id, case.id)

    await session.execute(text('SET search_path = ag_catalog, "$user", public;'))
    r = await session.execute(
        text(
            f"SELECT * FROM cypher('{GRAPH_NAME}', $$ "
            f"MATCH ()-[r {{id: '{rel.id}'}}]->() RETURN count(r) AS c "
            f"$$) AS (c agtype);"
        )
    )
    count = int(str(r.first()[0]).split("::")[0])
    assert count == 0

    # Cleanup vertices
    await delete_vertex(session, e1.id)
    await delete_vertex(session, e2.id)
    await session.commit()


# ---------------------------------------------------------------------------
# create_if_not_exists (dedup helper)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_if_not_exists_creates_when_absent(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    e1 = await _make_entity(db, case.id, user.id, "e1.example")
    e2 = await _make_entity(db, case.id, user.id, "e2.example")
    await db.commit()

    repo = RelationshipRepository(db)
    rel, created = await repo.create_if_not_exists(
        case.id,
        None,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.SUBDOMAIN_OF,
        ),
    )
    assert created is True
    assert rel.rel_type == "SUBDOMAIN_OF"


@pytest.mark.asyncio
async def test_create_if_not_exists_returns_existing(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    e1 = await _make_entity(db, case.id, user.id, "e1.example")
    e2 = await _make_entity(db, case.id, user.id, "e2.example")
    await db.commit()

    repo = RelationshipRepository(db)
    first, c1 = await repo.create_if_not_exists(
        case.id,
        None,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.SUBDOMAIN_OF,
        ),
    )
    second, c2 = await repo.create_if_not_exists(
        case.id,
        None,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.SUBDOMAIN_OF,
        ),
    )
    assert c1 is True and c2 is False
    assert first.id == second.id


@pytest.mark.asyncio
async def test_create_if_not_exists_different_rel_type_creates_new(db):
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    e1 = await _make_entity(db, case.id, user.id, "e1.example")
    e2 = await _make_entity(db, case.id, user.id, "e2.example")
    await db.commit()

    repo = RelationshipRepository(db)
    sub, _ = await repo.create_if_not_exists(
        case.id,
        None,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.SUBDOMAIN_OF,
        ),
    )
    owns, created = await repo.create_if_not_exists(
        case.id,
        None,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.OWNS,
        ),
    )
    assert created is True
    assert sub.id != owns.id


@pytest.mark.asyncio
async def test_create_if_not_exists_preserves_existing_confidence(db):
    """Immutable: second call with different confidence does NOT mutate."""
    user = await _make_user(db)
    case = await _make_case(db, user.id)
    e1 = await _make_entity(db, case.id, user.id, "e1.example")
    e2 = await _make_entity(db, case.id, user.id, "e2.example")
    await db.commit()

    repo = RelationshipRepository(db)
    first, _ = await repo.create_if_not_exists(
        case.id,
        None,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.SUBDOMAIN_OF,
            confidence=0.5,
        ),
    )
    second, created = await repo.create_if_not_exists(
        case.id,
        None,
        RelationshipCreate(
            src_entity_id=e1.id,
            dst_entity_id=e2.id,
            rel_type=RelationshipType.SUBDOMAIN_OF,
            confidence=0.99,
        ),
    )
    assert created is False
    assert second.confidence == 0.5  # original preserved
