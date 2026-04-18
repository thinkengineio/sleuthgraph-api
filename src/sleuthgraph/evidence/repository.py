"""Append-only Evidence repository: SQL row + MinIO blob in one operation.

The blob is uploaded BEFORE the SQL commit so a crash between the two leaves
an orphan blob (cheap) rather than a dangling DB row (which would 404 on blob
fetch). The blob key is content-addressed (sha256), so re-uploads are no-ops.
"""

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.evidence.hashing import hash_bytes
from sleuthgraph.evidence.models import Evidence
from sleuthgraph.evidence.schemas import EvidenceCreate
from sleuthgraph.evidence.storage import EvidenceStorage, build_key


class EvidenceRepository:
    """Append-only repository. No update, no delete — by design."""

    def __init__(self, session: AsyncSession, storage: EvidenceStorage) -> None:
        self.session = session
        self.storage = storage

    async def create(
        self,
        case_id: uuid.UUID,
        created_by: uuid.UUID | None,
        data: EvidenceCreate,
        payload: bytes,
        content_type: str | None,
    ) -> Evidence:
        """Hash payload → upload blob → insert row. All-or-nothing."""
        response_hash = hash_bytes(payload)
        response_uri = build_key(str(case_id), response_hash)
        content_type_final = content_type or "application/octet-stream"

        evidence = Evidence(
            case_id=case_id,
            entity_id=data.entity_id,
            source_plugin=data.source_plugin,
            query=data.query,
            response_hash=response_hash,
            response_uri=response_uri,
            response_bytes=len(payload),
            response_content_type=content_type_final if content_type else None,
            reproducibility_spec=data.reproducibility_spec,
            created_by=created_by,
        )
        self.session.add(evidence)
        await self.session.flush()

        try:
            await self.storage.put(response_uri, payload, content_type_final)
            await self.session.commit()
        except Exception:
            await self.session.rollback()
            raise

        await self.session.refresh(evidence)
        return evidence

    async def get(
        self, ev_id: uuid.UUID, case_id: uuid.UUID,
    ) -> Evidence | None:
        q = select(Evidence).where(
            Evidence.id == ev_id,
            Evidence.case_id == case_id,
        )
        return (await self.session.execute(q)).scalar_one_or_none()

    async def list_for_case(
        self,
        case_id: uuid.UUID,
        entity_id: uuid.UUID | None = None,
        source_plugin: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[Sequence[Evidence], int]:
        """Returns (items, total_count) for paginated responses."""
        base_filter = [Evidence.case_id == case_id]
        if entity_id is not None:
            base_filter.append(Evidence.entity_id == entity_id)
        if source_plugin is not None:
            base_filter.append(Evidence.source_plugin == source_plugin)

        count_q = select(func.count()).select_from(Evidence).where(*base_filter)
        total = (await self.session.execute(count_q)).scalar_one()

        items_q = (
            select(Evidence).where(*base_filter)
            .order_by(Evidence.timestamp.desc())
            .limit(limit).offset(offset)
        )
        items = list((await self.session.execute(items_q)).scalars())
        return items, total
