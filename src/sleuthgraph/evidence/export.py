"""Evidence ledger export (JSON or CSV) for chain-of-custody handoff."""

import csv
import io
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.auth.deps import current_active_user
from sleuthgraph.auth.models import User
from sleuthgraph.cases.repository import CaseRepository
from sleuthgraph.db import get_session
from sleuthgraph.evidence.repository import EvidenceRepository
from sleuthgraph.evidence.schemas import EvidenceRead
from sleuthgraph.evidence.storage import EvidenceStorage

router = APIRouter(prefix="/cases/{case_id}/evidence", tags=["evidence"])


CSV_COLUMNS = [
    "id", "timestamp", "source_plugin", "query",
    "response_hash", "response_bytes", "response_content_type",
    "entity_id", "reproducibility_spec",
]


def _get_storage() -> EvidenceStorage:
    return EvidenceStorage()


@router.get("/export")
async def export_evidence_ledger(
    case_id: uuid.UUID,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
    storage: EvidenceStorage = Depends(_get_storage),
):
    # Ownership check
    case_repo = CaseRepository(session)
    case = await case_repo.get(case_id, user.id)
    if case is None:
        raise HTTPException(status_code=404, detail="not found")

    repo = EvidenceRepository(session, storage)
    # Pull everything — cap at a large bound to prevent runaway
    items, _total = await repo.list_for_case(case_id, limit=100_000, offset=0)

    if format == "json":
        payload = {
            "case_id": str(case_id),
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "items": [
                EvidenceRead.model_validate(e).model_dump(mode="json")
                for e in items
            ],
        }
        return JSONResponse(content=payload)

    # CSV
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for e in items:
        writer.writerow([
            str(e.id),
            e.timestamp.isoformat() if e.timestamp else "",
            e.source_plugin,
            e.query,
            e.response_hash,
            e.response_bytes,
            e.response_content_type or "",
            str(e.entity_id) if e.entity_id else "",
            json.dumps(e.reproducibility_spec, sort_keys=True, separators=(",", ":")),
        ])

    filename = f"case-{case_id}-evidence.csv"
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
