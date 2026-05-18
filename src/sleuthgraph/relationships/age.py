"""Relationship-level AGE operations: upsert an edge, delete an edge.

Edge is between two existing vertices. Label = rel_type. Called in the
same SQL transaction as the relationship row so SQL + AGE stay in sync.
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.graph.age import _encode_props, run_cypher
from sleuthgraph.relationships.models import Relationship
from sleuthgraph.relationships.types import RelationshipType

_VALID_REL_TYPES = {t.value for t in RelationshipType}


async def upsert_edge(session: AsyncSession, rel: Relationship) -> None:
    """Create or merge the AGE edge for this relationship.

    MATCH the two endpoint vertices by their entity ids, MERGE the edge
    with a stable id property so repeat calls are idempotent.
    """
    # Defense-in-depth: rel_type is validated upstream via the
    # RelationshipType enum, but we re-check here at the point of Cypher
    # construction to prevent label injection if upstream validation is
    # ever bypassed.
    if rel.rel_type not in _VALID_REL_TYPES:
        raise ValueError(
            f"rel.rel_type {rel.rel_type!r} is not a valid RelationshipType; "
            f"refusing to construct Cypher label"
        )

    props = {
        "id": str(rel.id),
        "case_id": str(rel.case_id),
        "confidence": rel.confidence,
        "source_plugin": rel.source_plugin,
        "attrs": rel.attrs or {},
    }
    props_encoded = _encode_props(props)

    rel_type = rel.rel_type
    cypher = (
        f"MATCH (s {{id: '{rel.src_entity_id}'}}), "
        f"(d {{id: '{rel.dst_entity_id}'}}) "
        f"MERGE (s)-[r:{rel_type} {{id: '{rel.id}'}}]->(d) "
        f"SET r = {props_encoded} "
        f"RETURN r"
    )
    await run_cypher(session, cypher, return_col="r")


async def delete_edge(session: AsyncSession, rel_id: uuid.UUID) -> None:
    """Delete the edge with this relationship id (vertices preserved)."""
    cypher = f"MATCH ()-[r {{id: '{rel_id}'}}]->() DELETE r"
    await run_cypher(session, cypher, return_col="r")
