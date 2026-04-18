"""AGE vertex upsert/delete: requires live postgres + AGE extension.

Skipped automatically on sqlite-only test runs.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from sleuthgraph.entities.age import delete_vertex, upsert_vertex
from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.graph.age import GRAPH_NAME


def _make_entity(label="test-example.com", etype=EntityType.DOMAIN):
    now = datetime.now(timezone.utc)
    return Entity(
        id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        type=etype.value,
        label=label,
        attrs={"registrar": "Namecheap"},
        confidence=0.9,
        created_at=now,
        updated_at=now,
    )


async def _count_vertices_with_id(session, entity_id):
    await session.execute(text('SET search_path = ag_catalog, "$user", public;'))
    r = await session.execute(text(
        f"SELECT * FROM cypher('{GRAPH_NAME}', $$ "
        f"MATCH (v {{id: '{entity_id}'}}) RETURN count(v) AS c "
        f"$$) AS (c agtype);"
    ))
    row = r.first()
    # agtype is returned; strip trailing '::int' if present and parse
    raw = str(row[0])
    return int(raw.split("::")[0])


@pytest.mark.asyncio
async def test_upsert_vertex_creates_node(postgres_age_session):
    entity = _make_entity()
    await upsert_vertex(postgres_age_session, entity)
    await postgres_age_session.commit()
    count = await _count_vertices_with_id(postgres_age_session, entity.id)
    assert count == 1

    # Cleanup
    await delete_vertex(postgres_age_session, entity.id)
    await postgres_age_session.commit()


@pytest.mark.asyncio
async def test_upsert_is_idempotent(postgres_age_session):
    entity = _make_entity()
    await upsert_vertex(postgres_age_session, entity)
    await upsert_vertex(postgres_age_session, entity)  # second call should MERGE
    await postgres_age_session.commit()
    count = await _count_vertices_with_id(postgres_age_session, entity.id)
    assert count == 1

    # Cleanup
    await delete_vertex(postgres_age_session, entity.id)
    await postgres_age_session.commit()


@pytest.mark.asyncio
async def test_delete_vertex_removes_node(postgres_age_session):
    entity = _make_entity()
    await upsert_vertex(postgres_age_session, entity)
    await postgres_age_session.commit()
    await delete_vertex(postgres_age_session, entity.id)
    await postgres_age_session.commit()
    count = await _count_vertices_with_id(postgres_age_session, entity.id)
    assert count == 0


@pytest.mark.asyncio
async def test_label_with_quotes_does_not_inject(postgres_age_session):
    """If a user sets a label like "foo' SET something THE REST, the JSON-encoded
    property must neutralize the injection."""
    entity = _make_entity(label="evil' UNION MATCH (x) RETURN x //")
    await upsert_vertex(postgres_age_session, entity)
    await postgres_age_session.commit()
    # Vertex must exist with the literal string as its label (no injection)
    count = await _count_vertices_with_id(postgres_age_session, entity.id)
    assert count == 1

    # Cleanup
    await delete_vertex(postgres_age_session, entity.id)
    await postgres_age_session.commit()
