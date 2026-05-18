"""Entity-level AGE operations: upsert a vertex, delete a vertex.

Called from within the same SQL transaction as the entity row write so
either both or neither commit.
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.types import EntityType
from sleuthgraph.graph.age import _encode_props, run_cypher

_VALID_ENTITY_TYPES = {t.value for t in EntityType}


async def upsert_vertex(session: AsyncSession, entity: Entity) -> None:
    """Create or merge the AGE vertex for this entity.

    Label = entity.type (PERSON, DOMAIN, etc.). ID property lets us find
    the vertex by primary key later.
    """
    # Defense-in-depth: entity.type is validated upstream via the EntityType
    # enum, but we re-check here at the point of Cypher construction to
    # prevent label injection if upstream validation is ever bypassed.
    if entity.type not in _VALID_ENTITY_TYPES:
        raise ValueError(
            f"entity.type {entity.type!r} is not a valid EntityType; "
            f"refusing to construct Cypher label"
        )

    props = {
        "id": str(entity.id),
        "case_id": str(entity.case_id),
        "label": entity.label,
        "confidence": entity.confidence,
        "attrs": entity.attrs or {},
    }
    props_json = _encode_props(props)

    label = entity.type
    cypher = f"MERGE (v:{label} {{id: '{entity.id}'}}) SET v = {props_json} RETURN v"
    await run_cypher(session, cypher)


async def delete_vertex(session: AsyncSession, entity_id: uuid.UUID) -> None:
    """Detach-delete the vertex (also removes incident edges)."""
    cypher = f"MATCH (v {{id: '{entity_id}'}}) DETACH DELETE v"
    await run_cypher(session, cypher)
