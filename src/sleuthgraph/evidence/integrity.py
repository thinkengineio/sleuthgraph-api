"""Evidence integrity verification: re-hash blobs and compare against stored digests.

The sweeper iterates ALL evidence records across cases (admin-scope) and
returns a list of mismatches. It is callable but not wired to a cron — callers
decide scheduling.
"""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sleuthgraph.evidence.hashing import hash_bytes
from sleuthgraph.evidence.models import Evidence
from sleuthgraph.evidence.storage import EvidenceStorage


@dataclass(frozen=True)
class HashMismatch:
    """A single integrity violation."""

    ev_id: uuid.UUID
    case_id: uuid.UUID
    expected: str
    actual: str


async def verify_single(
    ev: Evidence,
    storage: EvidenceStorage,
) -> HashMismatch | None:
    """Re-read the blob from storage and compare its SHA-256 to the DB record.

    Returns a HashMismatch if the hashes diverge, None if intact.
    """
    blob = await storage.get(ev.response_uri)
    actual = hash_bytes(blob)
    if actual != ev.response_hash:
        return HashMismatch(
            ev_id=ev.id,
            case_id=ev.case_id,
            expected=ev.response_hash,
            actual=actual,
        )
    return None


async def sweep_all(
    session: AsyncSession,
    storage: EvidenceStorage,
) -> list[HashMismatch]:
    """Check every evidence record. Returns only mismatches (empty = healthy)."""
    q = select(Evidence).order_by(Evidence.timestamp.asc())
    result = await session.execute(q)
    records = list(result.scalars())

    mismatches: list[HashMismatch] = []
    for ev in records:
        mismatch = await verify_single(ev, storage)
        if mismatch is not None:
            mismatches.append(mismatch)
    return mismatches
