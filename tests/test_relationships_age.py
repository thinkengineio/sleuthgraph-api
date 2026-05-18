"""AGE edge upsert/delete: requires live postgres + AGE."""

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from sleuthgraph.auth.models import User
from sleuthgraph.cases.models import Case
from sleuthgraph.entities.age import upsert_vertex
from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.graph.age import GRAPH_NAME
from sleuthgraph.relationships.age import delete_edge, upsert_edge
from sleuthgraph.relationships.models import Relationship
from sleuthgraph.relationships.types import RelationshipType


async def _seed_case_and_two_entities(session):
    """Insert one user, one case, two entities with AGE vertices."""
    user_id = uuid.uuid4()
    case_id = uuid.uuid4()
    session.add(
        User(
            id=user_id,
            email=f"u-{user_id}@x.com",
            hashed_password="x",
            is_active=True,
            is_superuser=False,
            is_verified=False,
        )
    )
    session.add(Case(id=case_id, owner_id=user_id, name="T", tags=[]))
    await session.flush()

    now = datetime.now(UTC)
    e1 = Entity(
        id=uuid.uuid4(),
        case_id=case_id,
        type=EntityType.DOMAIN.value,
        label="src.example",
        attrs={},
        confidence=1.0,
        created_by=user_id,
        created_at=now,
        updated_at=now,
    )
    e2 = Entity(
        id=uuid.uuid4(),
        case_id=case_id,
        type=EntityType.IP_ADDRESS.value,
        label="203.0.113.5",
        attrs={},
        confidence=1.0,
        created_by=user_id,
        created_at=now,
        updated_at=now,
    )
    session.add_all([e1, e2])
    await session.flush()
    await upsert_vertex(session, e1)
    await upsert_vertex(session, e2)
    await session.commit()
    return case_id, e1, e2, user_id


def _make_rel(case_id, src_id, dst_id, rel_type=RelationshipType.RESOLVES_TO):
    now = datetime.now(UTC)
    return Relationship(
        id=uuid.uuid4(),
        case_id=case_id,
        src_entity_id=src_id,
        dst_entity_id=dst_id,
        rel_type=rel_type.value,
        confidence=0.8,
        source_plugin=None,
        attrs={},
        created_at=now,
    )


async def _count_edges_with_id(session, rel_id):
    await session.execute(text('SET search_path = ag_catalog, "$user", public;'))
    r = await session.execute(
        text(
            f"SELECT * FROM cypher('{GRAPH_NAME}', $$ "
            f"MATCH ()-[r {{id: '{rel_id}'}}]->() RETURN count(r) AS c "
            f"$$) AS (c agtype);"
        )
    )
    row = r.first()
    return int(str(row[0]).split("::")[0])


@pytest.mark.asyncio
async def test_upsert_edge_creates_edge(postgres_age_session):
    case_id, e1, e2, _ = await _seed_case_and_two_entities(postgres_age_session)
    rel = _make_rel(case_id, e1.id, e2.id)

    await upsert_edge(postgres_age_session, rel)
    await postgres_age_session.commit()

    count = await _count_edges_with_id(postgres_age_session, rel.id)
    assert count == 1

    # Cleanup
    await delete_edge(postgres_age_session, rel.id)
    await postgres_age_session.commit()


@pytest.mark.asyncio
async def test_upsert_edge_is_idempotent(postgres_age_session):
    case_id, e1, e2, _ = await _seed_case_and_two_entities(postgres_age_session)
    rel = _make_rel(case_id, e1.id, e2.id)

    await upsert_edge(postgres_age_session, rel)
    await upsert_edge(postgres_age_session, rel)
    await postgres_age_session.commit()

    count = await _count_edges_with_id(postgres_age_session, rel.id)
    assert count == 1

    await delete_edge(postgres_age_session, rel.id)
    await postgres_age_session.commit()


@pytest.mark.asyncio
async def test_delete_edge_removes_it(postgres_age_session):
    case_id, e1, e2, _ = await _seed_case_and_two_entities(postgres_age_session)
    rel = _make_rel(case_id, e1.id, e2.id)

    await upsert_edge(postgres_age_session, rel)
    await postgres_age_session.commit()

    await delete_edge(postgres_age_session, rel.id)
    await postgres_age_session.commit()

    count = await _count_edges_with_id(postgres_age_session, rel.id)
    assert count == 0


@pytest.mark.asyncio
async def test_self_loop_is_allowed(postgres_age_session):
    """ASSOCIATED_WITH etc. can legitimately be self-loops."""
    case_id, e1, _, _ = await _seed_case_and_two_entities(postgres_age_session)
    rel = _make_rel(case_id, e1.id, e1.id, RelationshipType.ASSOCIATED_WITH)
    await upsert_edge(postgres_age_session, rel)
    await postgres_age_session.commit()

    count = await _count_edges_with_id(postgres_age_session, rel.id)
    assert count == 1

    await delete_edge(postgres_age_session, rel.id)
    await postgres_age_session.commit()


@pytest.mark.asyncio
async def test_dollar_quote_in_source_plugin_does_not_inject(postgres_age_session):
    """A source_plugin value containing '$$' must not escape the dollar-quote tag.

    Validates the random-tag fix (C1) on the relationship path: the delimiter
    is unique per call, so embedded $$ in string properties is inert.
    """
    case_id, e1, e2, _ = await _seed_case_and_two_entities(postgres_age_session)
    now = datetime.now(UTC)
    rel = Relationship(
        id=uuid.uuid4(),
        case_id=case_id,
        src_entity_id=e1.id,
        dst_entity_id=e2.id,
        rel_type=RelationshipType.RESOLVES_TO.value,
        confidence=0.9,
        source_plugin="plugin$$; DROP TABLE users; --",
        attrs={},
        created_at=now,
    )

    # Must not raise; $$ in source_plugin is data inside random-tagged delimiters.
    await upsert_edge(postgres_age_session, rel)
    await postgres_age_session.commit()

    count = await _count_edges_with_id(postgres_age_session, rel.id)
    assert count == 1

    # The users table still exists — confirms no DDL injection ran.
    from sqlalchemy import text as _t

    r = await postgres_age_session.execute(_t("SELECT count(*) FROM users"))
    assert r.scalar() >= 0

    # Cleanup
    await delete_edge(postgres_age_session, rel.id)
    await postgres_age_session.commit()
