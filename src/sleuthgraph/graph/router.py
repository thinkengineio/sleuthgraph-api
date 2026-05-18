"""Read-only flat-graph endpoint for Cytoscape-friendly rendering.

Returns ALL live entities + relationships for a case. No AGE involvement —
Phase 9 adds Cypher-backed endpoints; this baseline is SQL-only.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.deps import current_active_user
from sleuthgraph.auth.models import User
from sleuthgraph.cases.repository import CaseRepository
from sleuthgraph.db import get_session
from sleuthgraph.entities.repository import EntityRepository
from sleuthgraph.relationships.repository import RelationshipRepository

router = APIRouter(prefix="/cases/{case_id}/graph", tags=["graph"])


class GraphVertex(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    type: str
    label: str
    confidence: float
    attrs: dict


class GraphEdge(BaseModel):
    id: uuid.UUID
    source: uuid.UUID
    target: uuid.UUID
    rel_type: str
    confidence: float
    source_plugin: str | None
    attrs: dict


_GRAPH_LIMIT = 10_000


class GraphDump(BaseModel):
    vertices: list[GraphVertex]
    edges: list[GraphEdge]
    truncated: bool = False


@router.get("", response_model=GraphDump)
async def get_graph(
    case_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> GraphDump:
    # Ownership check
    case_repo = CaseRepository(session)
    case = await case_repo.get(case_id, user.id)
    if case is None:
        raise HTTPException(status_code=404, detail="not found")

    entity_repo = EntityRepository(session)
    rel_repo = RelationshipRepository(session)

    # Fetch limit+1 so we can detect whether results were truncated
    entities = await entity_repo.list_for_case(
        case_id, limit=_GRAPH_LIMIT + 1, offset=0,
    )
    rels = await rel_repo.list_for_case(
        case_id, limit=_GRAPH_LIMIT + 1, offset=0,
    )

    truncated = len(entities) > _GRAPH_LIMIT or len(rels) > _GRAPH_LIMIT
    entities = entities[:_GRAPH_LIMIT]
    rels = rels[:_GRAPH_LIMIT]

    vertices = [
        GraphVertex(
            id=e.id, type=e.type, label=e.label,
            confidence=e.confidence, attrs=e.attrs or {},
        )
        for e in entities
    ]
    edges = [
        GraphEdge(
            id=r.id,
            source=r.src_entity_id,
            target=r.dst_entity_id,
            rel_type=r.rel_type,
            confidence=r.confidence,
            source_plugin=r.source_plugin,
            attrs=r.attrs or {},
        )
        for r in rels
    ]
    return GraphDump(vertices=vertices, edges=edges, truncated=truncated)
