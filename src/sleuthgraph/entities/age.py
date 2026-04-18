"""Entity-level AGE operations: upsert a vertex, delete a vertex.

Called from within the same SQL transaction as the entity row write so
either both or neither commit.
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.entities.models import Entity
from sleuthgraph.graph.age import _encode_props, run_cypher


async def upsert_vertex(session: AsyncSession, entity: Entity) -> None:
    """Create or merge the AGE vertex for this entity.

    Label = entity.type (PERSON, DOMAIN, etc.). ID property lets us find
    the vertex by primary key later.
    """
    props = {
        "id": str(entity.id),
        "case_id": str(entity.case_id),
        "label": entity.label,
        "confidence": entity.confidence,
        "attrs": entity.attrs or {},
    }
    props_json = _encode_props(props)

    # NOTE: entity.type is validated against the EntityType enum upstream,
    # so it is NOT user-controlled free text. Still, avoid backticks and
    # keep the label alphanumeric by construction.
    label = entity.type
    cypher = (
        f"MERGE (v:{label} {{id: '{entity.id}'}}) "
        f"SET v = {props_json} "
        f"RETURN v"
    )
    await run_cypher(session, cypher)


async def delete_vertex(session: AsyncSession, entity_id: uuid.UUID) -> None:
    """Detach-delete the vertex (also removes incident edges)."""
    cypher = (
        f"MATCH (v {{id: '{entity_id}'}}) "
        f"DETACH DELETE v"
    )
    await run_cypher(session, cypher)
