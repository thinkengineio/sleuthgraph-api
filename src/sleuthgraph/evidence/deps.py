"""Shared FastAPI dependencies for the evidence routers.

Single source of truth for the EvidenceStorage dependency — tests can
override ``get_storage`` once to swap in a fake for both the POST router
and the export router.
"""

from sleuthgraph.evidence.storage import EvidenceStorage


def get_storage() -> EvidenceStorage:
    return EvidenceStorage()
