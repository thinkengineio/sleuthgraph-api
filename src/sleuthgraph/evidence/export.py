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
from sleuthgraph.evidence.deps import get_storage
from sleuthgraph.evidence.repository import EvidenceRepository
from sleuthgraph.evidence.schemas import EvidenceRead
from sleuthgraph.evidence.storage import EvidenceStorage

router = APIRouter(prefix="/cases/{case_id}/evidence", tags=["evidence"])


CSV_COLUMNS = [
    "id", "timestamp", "source_plugin", "query",
    "response_hash", "response_bytes", "response_content_type",
    "entity_id", "reproducibility_spec",
]

_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _csv_safe(value) -> str:
    """Neutralize CSV injection (CWE-1236) by prefixing leading formula chars.

    Excel and LibreOffice interpret cells that start with =, +, -, or @ as
    formulas when a CSV is opened. Prefixing a single quote suppresses that
    interpretation without altering the logical value for non-spreadsheet
    consumers.
    """
    s = "" if value is None else str(value)
    if s.startswith(_FORMULA_PREFIXES):
        return "'" + s
    return s


@router.get("/export")
async def export_evidence_ledger(
    case_id: uuid.UUID,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_session),
    storage: EvidenceStorage = Depends(get_storage),
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

    # CSV — UUIDs, integers, hex digests, and ISO timestamps are safe by
    # construction (no leading formula chars possible). Only user-controlled
    # text fields need the _csv_safe guard.
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for e in items:
        writer.writerow([
            str(e.id),
            e.timestamp.isoformat() if e.timestamp else "",
            _csv_safe(e.source_plugin),
            _csv_safe(e.query),
            e.response_hash,  # hex digest — safe
            e.response_bytes,
            _csv_safe(e.response_content_type or ""),
            str(e.entity_id) if e.entity_id else "",
            _csv_safe(json.dumps(e.reproducibility_spec, sort_keys=True, separators=(",", ":"))),
        ])

    filename = f"case-{case_id}-evidence.csv"
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
