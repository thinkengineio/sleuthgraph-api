"""arq task: run_plugin_task.

Wraps PluginRunner for out-of-band execution.  Task receives the already-created
PluginRun.id (dispatcher inserted it with status=queued) and executes the runner.
Idempotent: if the row is no longer queued (already running or finished), returns
early without re-executing.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sleuthgraph.db import get_session_factory
from sleuthgraph.entities.models import Entity
from sleuthgraph.evidence.deps import get_storage_for_worker
from sleuthgraph.plugins.models import PluginRun
from sleuthgraph.plugins.registry import PluginRegistry
from sleuthgraph.plugins.runner import PluginRunner

log = logging.getLogger(__name__)


async def run_plugin_task(ctx: dict[str, Any], run_id: str) -> dict[str, str | int]:
    """arq task entrypoint.

    ``ctx`` may be overridden in tests with:
      - ``session_factory``  — override of ``get_session_factory()`` result
      - ``registry``         — pre-built PluginRegistry (else built from defaults)
      - ``storage``          — EvidenceStorage (else built via deps helper)
    """
    session_factory = ctx.get("session_factory") or get_session_factory()
    registry: PluginRegistry = ctx.get("registry") or _build_registry()
    storage = ctx.get("storage") or get_storage_for_worker()

    run_uuid = uuid.UUID(run_id)

    async with session_factory() as session:
        run = await session.get(PluginRun, run_uuid)
        if run is None:
            log.warning("run_plugin_task: run_id %s not found", run_id)
            return {"status": "not_found"}

        if run.status != "queued":
            log.info(
                "run_plugin_task: %s already %s, skipping",
                run_id,
                run.status,
            )
            return {"status": "skipped", "reason": "not_queued"}

        # Load input entity
        input_entity: Entity | None = None
        if run.input_entity_id is not None:
            input_entity = await session.get(Entity, run.input_entity_id)
        if input_entity is None:
            run.status = "failed"
            run.error_message = "missing_input_entity"
            await session.commit()
            return {"status": "failed", "reason": "missing_input_entity"}

        # Flip to running atomically before handing off to the runner. A
        # concurrent call will see status != "queued" and bail.
        run.status = "running"
        await session.commit()

        runner = PluginRunner(session, storage, registry)
        try:
            result = await runner.run(
                run.plugin_name,
                run.case_id,
                input_entity,
                created_by=run.created_by,
                existing_run=run,
            )
        except Exception as exc:
            log.exception("plugin task %s failed", run_id)
            return {"status": "failed", "reason": type(exc).__name__}

        return {
            "status": "succeeded",
            "entities": result.run.entities_created_count,
            "relationships": result.run.relationships_created_count,
            "evidence": result.run.evidence_count,
        }


def _build_registry() -> PluginRegistry:
    # Local import to avoid circular-at-module-load.
    from sleuthgraph.plugins import PLUGINS

    return PluginRegistry(PLUGINS)
