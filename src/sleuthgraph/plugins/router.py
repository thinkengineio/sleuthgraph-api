"""HTTP router for /plugins and /cases/{id}/plugins/*."""

import uuid

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.deps import current_active_user
from sleuthgraph.auth.models import User
from sleuthgraph.cases.repository import CaseRepository
from sleuthgraph.db import get_session
from sleuthgraph.entities.repository import EntityRepository
from sleuthgraph.entities.schemas import EntityRead
from sleuthgraph.evidence.deps import get_storage
from sleuthgraph.evidence.schemas import EvidenceRead
from sleuthgraph.evidence.storage import EvidenceStorage
from sleuthgraph.plugins.deps import get_registry
from sleuthgraph.plugins.models import PluginRun
from sleuthgraph.plugins.registry import PluginNotFoundError, PluginRegistry
from sleuthgraph.plugins.repository import PluginRunRepository
from sleuthgraph.plugins.runner import PluginExecutionError, PluginTypeError, PluginRunner
from sleuthgraph.plugins.schemas import (
    PluginInfo,
    PluginRunList,
    PluginRunRead,
)
from sleuthgraph.relationships.schemas import RelationshipRead

registry_router = APIRouter(prefix="/plugins", tags=["plugins"])
case_router = APIRouter(
    prefix="/cases/{case_id}/plugins", tags=["plugins"],
)


def _plugin_info(plugin) -> PluginInfo:
    return PluginInfo(
        name=plugin.name,
        version=plugin.version,
        entity_types_accepted=plugin.entity_types_accepted,
        entity_types_produced=plugin.entity_types_produced,
        requires_credentials=plugin.requires_credentials,
    )


@registry_router.get("", response_model=list[PluginInfo])
async def list_plugins(
    user: User = Depends(current_active_user),
    registry: PluginRegistry = Depends(get_registry),
) -> list[PluginInfo]:
    return [_plugin_info(p) for p in registry.list()]


@registry_router.get("/{name}", response_model=PluginInfo)
async def get_plugin(
    name: str,
    user: User = Depends(current_active_user),
    registry: PluginRegistry = Depends(get_registry),
) -> PluginInfo:
    try:
        plugin = registry.get(name)
    except PluginNotFoundError:
        raise HTTPException(status_code=404, detail="plugin not found")
    return _plugin_info(plugin)


async def _verify_case_ownership(case_id, user, session):
    case_repo = CaseRepository(session)
    case = await case_repo.get(case_id, user.id)
    if case is None:
        raise HTTPException(status_code=404, detail="not found")


@case_router.post("/{plugin_name}/run")
async def run_plugin(
    case_id: uuid.UUID,
    plugin_name: str,
    body: dict = Body(...),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
    registry: PluginRegistry = Depends(get_registry),
    storage: EvidenceStorage = Depends(get_storage),
) -> JSONResponse:
    await _verify_case_ownership(case_id, user, session)

    # Validate body
    input_entity_id_raw = body.get("input_entity_id")
    if not input_entity_id_raw:
        raise HTTPException(status_code=422, detail="input_entity_id is required")
    try:
        input_entity_id = uuid.UUID(str(input_entity_id_raw))
    except ValueError:
        raise HTTPException(status_code=422, detail="input_entity_id must be a UUID")

    # Load input entity (must be in this case)
    entity_repo = EntityRepository(session)
    input_entity = await entity_repo.get(input_entity_id, case_id)
    if input_entity is None:
        raise HTTPException(status_code=404, detail="input entity not in case")

    # Validate plugin exists
    try:
        plugin = registry.get(plugin_name)
    except PluginNotFoundError:
        raise HTTPException(status_code=404, detail="plugin not found") from None

    if plugin.dispatch_mode == "async":
        # Create row with status=queued, enqueue task, return 202.
        run = PluginRun(
            case_id=case_id,
            input_entity_id=input_entity.id,
            plugin_name=plugin.name,
            plugin_version=plugin.version,
            status="queued",
            created_by=user.id,
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)

        from sleuthgraph.queue import enqueue as _enqueue

        try:
            await _enqueue.enqueue_plugin_run(run.id)
        except Exception as exc:
            # Mark row failed so the UI doesn't show stuck "queued" forever.
            run.status = "failed"
            run.error_message = "enqueue_failed"
            await session.commit()
            raise HTTPException(
                status_code=503, detail="worker unavailable"
            ) from exc

        return JSONResponse(
            status_code=202,
            content={
                "run": PluginRunRead.model_validate(run).model_dump(mode="json"),
                "entities": [],
                "relationships": [],
                "evidence": [],
            },
        )

    # Sync path (unchanged from Phase 5)
    runner = PluginRunner(session, storage, registry)

    try:
        result = await runner.run(
            plugin_name, case_id, input_entity, created_by=user.id,
        )
    except PluginTypeError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    except PluginExecutionError as e:
        raise HTTPException(status_code=500, detail="plugin execution failed") from e

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "run": PluginRunRead.model_validate(result.run).model_dump(mode="json"),
            "entities": [
                EntityRead.model_validate(e).model_dump(mode="json")
                for e in result.entities_created
            ],
            "relationships": [
                RelationshipRead.model_validate(r).model_dump(mode="json")
                for r in result.relationships_created
            ],
            "evidence": [
                EvidenceRead.model_validate(ev).model_dump(mode="json")
                for ev in result.evidence_created
            ],
        },
    )


@case_router.get("/runs", response_model=PluginRunList)
async def list_runs(
    case_id: uuid.UUID,
    status_filter: str | None = Query(default=None, alias="status"),
    plugin_name: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> PluginRunList:
    await _verify_case_ownership(case_id, user, session)
    repo = PluginRunRepository(session)
    items, total = await repo.list_for_case(
        case_id, status=status_filter, plugin_name=plugin_name,
        limit=limit, offset=offset,
    )
    return PluginRunList(
        items=[PluginRunRead.model_validate(r) for r in items],
        total=total, limit=limit, offset=offset,
    )


@case_router.get("/runs/{run_id}", response_model=PluginRunRead)
async def get_run(
    case_id: uuid.UUID,
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
) -> PluginRunRead:
    await _verify_case_ownership(case_id, user, session)
    repo = PluginRunRepository(session)
    run = await repo.get(run_id, case_id)
    if run is None:
        raise HTTPException(status_code=404, detail="not found")
    return PluginRunRead.model_validate(run)
