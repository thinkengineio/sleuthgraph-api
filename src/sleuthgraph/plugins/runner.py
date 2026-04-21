"""PluginRunner — orchestrates plugin execution with dedup + audit.

Sync in-request for MVP (no job queue). Plugin produces proposals; runner:
  1. Creates PluginRun audit row (status=running)
  2. Calls plugin.query(input_entity, credentials, context)
  3. Resolves EntityProposal refs via EntityRepository.get_or_create (dedup)
  4. Writes RelationshipProposal via RelationshipRepository.create_if_not_exists (dedup)
  5. Writes EvidenceProposal via EvidenceRepository.create (content-addressed dedup in MinIO)
  6. Updates PluginRun to status=succeeded with counts; or status=failed with error_message
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.entities.models import Entity
from sleuthgraph.entities.repository import EntityRepository
from sleuthgraph.entities.schemas import EntityCreate
from sleuthgraph.evidence.repository import EvidenceRepository
from sleuthgraph.evidence.schemas import EvidenceCreate
from sleuthgraph.evidence.storage import EvidenceStorage
from sleuthgraph.plugins.base import (
    EntityProposal,
    EvidenceProposal,
    OSINTPlugin,
    PluginContext,
    QueryResult,
    RelationshipProposal,
)
from sleuthgraph.plugins.models import PluginRun
from sleuthgraph.plugins.registry import PluginRegistry
from sleuthgraph.relationships.repository import RelationshipRepository
from sleuthgraph.relationships.schemas import RelationshipCreate

log = logging.getLogger(__name__)


class PluginExecutionError(RuntimeError):
    """Raised by the runner when a plugin throws; wraps the original exception."""


class RunResult:
    """What the runner returns to the HTTP layer."""

    def __init__(
        self,
        run: PluginRun,
        entities_created: list[Entity],
        relationships_created: list,
        evidence_created: list,
    ) -> None:
        self.run = run
        self.entities_created = entities_created
        self.relationships_created = relationships_created
        self.evidence_created = evidence_created


class PluginRunner:
    """Runs a plugin against an input entity, persists results, audits the run."""

    def __init__(
        self,
        session: AsyncSession,
        storage: EvidenceStorage,
        registry: PluginRegistry,
    ) -> None:
        self.session = session
        self.storage = storage
        self.registry = registry

    async def run(
        self,
        plugin_name: str,
        case_id: uuid.UUID,
        input_entity: Entity,
        created_by: uuid.UUID | None,
        credentials: dict | None = None,
    ) -> RunResult:
        plugin = self.registry.get(plugin_name)

        # Validate input entity type is accepted
        from sleuthgraph.entities.types import EntityType
        try:
            input_type = EntityType(input_entity.type)
        except ValueError:
            raise PluginExecutionError(
                f"unknown entity type: {input_entity.type}"
            )
        if input_type not in plugin.entity_types_accepted:
            raise PluginExecutionError(
                f"plugin {plugin.name} does not accept entity type {input_entity.type}"
            )

        # Audit row: running
        run = PluginRun(
            case_id=case_id,
            input_entity_id=input_entity.id,
            plugin_name=plugin.name,
            plugin_version=plugin.version,
            status="running",
            created_by=created_by,
        )
        self.session.add(run)
        await self.session.commit()
        await self.session.refresh(run)

        try:
            async with httpx.AsyncClient(timeout=plugin.http_timeout_seconds) as http_client:
                ctx = PluginContext(
                    case_id=str(case_id),
                    input_entity=input_entity,
                    http_client=http_client,
                )
                result: QueryResult = await plugin.query(
                    input_entity, credentials, ctx,
                )

            entities_created, rels_created, evidence_created = await self._persist(
                case_id, input_entity, created_by, plugin.full_name, result,
            )

            # Audit row: succeeded
            run.status = "succeeded"
            run.finished_at = datetime.now(timezone.utc)
            run.entities_created_count = len(entities_created)
            run.relationships_created_count = len(rels_created)
            run.evidence_count = len(evidence_created)
            await self.session.commit()
            await self.session.refresh(run)

            return RunResult(run, entities_created, rels_created, evidence_created)

        except Exception as e:
            # Ensure audit row captures the failure
            run.status = "failed"
            run.finished_at = datetime.now(timezone.utc)
            run.error_message = str(e)[:2000]
            try:
                await self.session.commit()
            except Exception:
                log.exception("failed to persist PluginRun failure state")
            if isinstance(e, PluginExecutionError):
                raise
            raise PluginExecutionError(f"plugin {plugin.name} failed: {e}") from e

    async def _persist(
        self,
        case_id: uuid.UUID,
        input_entity: Entity,
        created_by: uuid.UUID | None,
        plugin_full_name: str,
        result: QueryResult,
    ) -> tuple[list, list, list]:
        """Resolve proposals → real rows with dedup."""
        entity_repo = EntityRepository(self.session)
        rel_repo = RelationshipRepository(self.session)
        evidence_repo = EvidenceRepository(self.session, self.storage)

        # Map EntityProposal.ref → resolved Entity
        ref_to_entity: dict[str, Entity] = {}
        entities_created: list[Entity] = []
        for ep in result.entities:
            entity, was_created = await entity_repo.get_or_create(
                case_id, created_by,
                EntityCreate(
                    type=ep.type,
                    label=ep.label,
                    attrs=ep.attrs,
                    confidence=ep.confidence,
                ),
            )
            ref_to_entity[ep.ref] = entity
            if was_created:
                entities_created.append(entity)

        rels_created = []
        for rp in result.relationships:
            src_entity = self._resolve_ref(rp.src, input_entity, ref_to_entity)
            dst_entity = self._resolve_ref(rp.dst, input_entity, ref_to_entity)
            rel, was_created = await rel_repo.create_if_not_exists(
                case_id, created_by,
                RelationshipCreate(
                    src_entity_id=src_entity.id,
                    dst_entity_id=dst_entity.id,
                    rel_type=rp.rel_type,
                    confidence=rp.confidence,
                    source_plugin=plugin_full_name,
                    attrs=rp.attrs,
                ),
            )
            if was_created:
                rels_created.append(rel)

        evidence_created = []
        for evp in result.evidence:
            link_entity_id = input_entity.id if evp.link_to_input else None
            ev = await evidence_repo.create(
                case_id, created_by,
                EvidenceCreate(
                    entity_id=link_entity_id,
                    source_plugin=plugin_full_name,
                    query=evp.query,
                    reproducibility_spec=evp.reproducibility_spec,
                ),
                evp.payload,
                evp.content_type,
            )
            evidence_created.append(ev)

        return entities_created, rels_created, evidence_created

    @staticmethod
    def _resolve_ref(
        ref: dict,
        input_entity: Entity,
        ref_to_entity: dict,
    ) -> Entity:
        if ref.get("input"):
            return input_entity
        if "ref" in ref:
            ref_key = ref["ref"]
            if ref_key not in ref_to_entity:
                raise PluginExecutionError(
                    f"proposal references unknown entity ref: {ref_key!r}"
                )
            return ref_to_entity[ref_key]
        raise PluginExecutionError(
            f"relationship endpoint must have 'input' or 'ref' key, got: {ref}"
        )
