"""HTTP router for /cases/{case_id}/evidence (append-only: POST + GET only)."""

import uuid

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.deps import current_active_user
from sleuthgraph.auth.models import User
from sleuthgraph.cases.repository import CaseRepository
from sleuthgraph.config import get_settings
from sleuthgraph.db import get_session
from sleuthgraph.evidence.deps import get_storage
from sleuthgraph.evidence.repository import EvidenceRepository
from sleuthgraph.evidence.schemas import (
    EvidenceCreate,
    EvidenceList,
    EvidenceRead,
)
from sleuthgraph.evidence.storage import EvidenceStorage

router = APIRouter(prefix="/cases/{case_id}/evidence", tags=["evidence"])


async def _verify_case_ownership(
    case_id: uuid.UUID, user: User, session: AsyncSession,
) -> None:
    """Raise 404 if case doesn't exist or isn't owned by user (no-leak invariant)."""
    case_repo = CaseRepository(session)
    case = await case_repo.get(case_id, user.id)
    if case is None:
        raise HTTPException(status_code=404, detail="not found")


def _build_repo(
    session: AsyncSession = Depends(get_session),
    storage: EvidenceStorage = Depends(get_storage),
) -> EvidenceRepository:
    return EvidenceRepository(session, storage)


@router.post(
    "", response_model=EvidenceRead, status_code=status.HTTP_201_CREATED,
)
async def create_evidence(
    case_id: uuid.UUID,
    metadata: str = Form(...),
    file: UploadFile = File(...),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
    repo: EvidenceRepository = Depends(_build_repo),
) -> EvidenceRead:
    await _verify_case_ownership(case_id, user, session)

    max_bytes = get_settings().evidence_max_upload_bytes

    # Note: a Content-Length pre-check is not applied here because for
    # multipart requests the header reflects the full envelope (boundary +
    # all parts), not the file part alone. Comparing it against the per-file
    # cap would either produce false positives (rejecting valid uploads) or
    # require fragile headroom math. Guard 2 (bounded file.read) is the
    # precise, binding enforcement.

    try:
        data = EvidenceCreate.model_validate_json(metadata)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"invalid metadata: {e}")

    # Bounded read: request one byte beyond the limit so we can detect overflow
    # without buffering the full malicious payload.
    payload = await file.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"evidence payload exceeds {max_bytes} bytes",
        )

    ev = await repo.create(
        case_id, user.id, data, payload, file.content_type,
    )
    return EvidenceRead.model_validate(ev)


@router.get("", response_model=EvidenceList)
async def list_evidence(
    case_id: uuid.UUID,
    entity_id: uuid.UUID | None = Query(default=None),
    source_plugin: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
    repo: EvidenceRepository = Depends(_build_repo),
) -> EvidenceList:
    await _verify_case_ownership(case_id, user, session)
    items, total = await repo.list_for_case(
        case_id, entity_id=entity_id, source_plugin=source_plugin,
        limit=limit, offset=offset,
    )
    return EvidenceList(
        items=[EvidenceRead.model_validate(e) for e in items],
        total=total, limit=limit, offset=offset,
    )


@router.get("/{ev_id}", response_model=EvidenceRead)
async def get_evidence(
    case_id: uuid.UUID,
    ev_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
    repo: EvidenceRepository = Depends(_build_repo),
) -> EvidenceRead:
    await _verify_case_ownership(case_id, user, session)
    ev = await repo.get(ev_id, case_id)
    if ev is None:
        raise HTTPException(status_code=404, detail="not found")
    return EvidenceRead.model_validate(ev)


@router.get("/{ev_id}/blob")
async def get_evidence_blob(
    case_id: uuid.UUID,
    ev_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
    repo: EvidenceRepository = Depends(_build_repo),
) -> RedirectResponse:
    await _verify_case_ownership(case_id, user, session)
    ev = await repo.get(ev_id, case_id)
    if ev is None:
        raise HTTPException(status_code=404, detail="not found")
    url = await repo.storage.presign_get(ev.response_uri, expires_in=300)
    return RedirectResponse(url=url, status_code=307)
