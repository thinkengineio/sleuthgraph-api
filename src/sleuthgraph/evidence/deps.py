"""Shared FastAPI dependencies for the evidence routers.

Single source of truth for the EvidenceStorage dependency — tests can
override ``get_storage`` once to swap in a fake for both the POST router
and the export router.
"""

from sleuthgraph.evidence.storage import EvidenceStorage


def _storage_instance() -> EvidenceStorage:
    """Private factory — shared by request and worker code paths."""
    return EvidenceStorage()


def get_storage() -> EvidenceStorage:
    """FastAPI dependency: used inside request contexts."""
    return _storage_instance()


def get_storage_for_worker() -> EvidenceStorage:
    """Storage accessor for non-request contexts (arq worker, scripts)."""
    return _storage_instance()
