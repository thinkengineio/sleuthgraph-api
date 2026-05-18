"""RelationshipRepository: case-scoped CRUD (no update) with AGE mirror."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.entities.models import Entity
from sleuthgraph.relationships.age import delete_edge, upsert_edge
from sleuthgraph.relationships.models import Relationship
from sleuthgraph.relationships.schemas import RelationshipCreate


class EndpointNotInCaseError(ValueError):
    """Raised when src or dst entity isn't in the case."""


class RelationshipRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _assert_endpoints_in_case(
        self,
        case_id: uuid.UUID,
        src_id: uuid.UUID,
        dst_id: uuid.UUID,
    ) -> None:
        q = select(Entity.id).where(
            Entity.case_id == case_id,
            Entity.id.in_([src_id, dst_id]),
            Entity.deleted_at.is_(None),
        )
        rows = list((await self.session.execute(q)).scalars())
        expected = {src_id, dst_id}  # allows self-loop: set has one element
        if expected - set(rows):
            raise EndpointNotInCaseError(f"src/dst entities not found in case {case_id}")

    async def create(
        self,
        case_id: uuid.UUID,
        created_by: uuid.UUID | None,
        data: RelationshipCreate,
        *,
        commit: bool = True,
    ) -> Relationship:
        await self._assert_endpoints_in_case(
            case_id,
            data.src_entity_id,
            data.dst_entity_id,
        )
        rel = Relationship(
            case_id=case_id,
            src_entity_id=data.src_entity_id,
            dst_entity_id=data.dst_entity_id,
            rel_type=data.rel_type.value,
            confidence=data.confidence,
            source_plugin=data.source_plugin,
            attrs=data.attrs,
            created_by=created_by,
        )
        self.session.add(rel)
        await self.session.flush()
        try:
            await upsert_edge(self.session, rel)
            if commit:
                await self.session.commit()
        except Exception:
            await self.session.rollback()
            raise
        if commit:
            await self.session.refresh(rel)
        return rel

    async def create_if_not_exists(
        self,
        case_id: uuid.UUID,
        created_by: uuid.UUID | None,
        data: RelationshipCreate,
        *,
        commit: bool = True,
    ) -> tuple[Relationship, bool]:
        """Dedup on (case_id, src, dst, rel_type). Returns (rel, was_created).

        Immutable semantics: if a matching relationship exists, return it as-is
        without updating any fields (confidence, source_plugin, attrs).
        """
        q = select(Relationship).where(
            Relationship.case_id == case_id,
            Relationship.src_entity_id == data.src_entity_id,
            Relationship.dst_entity_id == data.dst_entity_id,
            Relationship.rel_type == data.rel_type.value,
            Relationship.deleted_at.is_(None),
        )
        existing = (await self.session.execute(q)).scalar_one_or_none()
        if existing is not None:
            return existing, False
        rel = await self.create(case_id, created_by, data, commit=commit)
        return rel, True

    async def get(
        self,
        rel_id: uuid.UUID,
        case_id: uuid.UUID,
    ) -> Relationship | None:
        q = select(Relationship).where(
            Relationship.id == rel_id,
            Relationship.case_id == case_id,
            Relationship.deleted_at.is_(None),
        )
        return (await self.session.execute(q)).scalar_one_or_none()

    async def list_for_case(
        self,
        case_id: uuid.UUID,
        rel_type: str | None = None,
        src: uuid.UUID | None = None,
        dst: uuid.UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Relationship]:
        q = select(Relationship).where(
            Relationship.case_id == case_id,
            Relationship.deleted_at.is_(None),
        )
        if rel_type:
            q = q.where(Relationship.rel_type == rel_type)
        if src:
            q = q.where(Relationship.src_entity_id == src)
        if dst:
            q = q.where(Relationship.dst_entity_id == dst)
        q = q.order_by(Relationship.created_at.desc()).limit(limit).offset(offset)
        return list((await self.session.execute(q)).scalars())

    async def soft_delete(
        self,
        rel_id: uuid.UUID,
        case_id: uuid.UUID,
    ) -> bool:
        rel = await self.get(rel_id, case_id)
        if rel is None:
            return False
        rel.deleted_at = datetime.now(UTC)
        await self.session.flush()
        try:
            await delete_edge(self.session, rel.id)
            await self.session.commit()
        except Exception:
            await self.session.rollback()
            raise
        return True
