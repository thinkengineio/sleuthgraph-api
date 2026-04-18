"""Pydantic schemas for Evidence — append-only, so no Update type."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sleuthgraph.graph.validators import _validate_attrs


class EvidenceCreate(BaseModel):
    """Evidence creation payload.

    Server computes response_hash, response_uri, response_bytes, timestamp.
    Client only provides what the evidence is ABOUT.
    """
    entity_id: uuid.UUID | None = None
    source_plugin: str = Field(default="manual", min_length=1, max_length=128)
    query: str = Field(min_length=1, max_length=1024)
    reproducibility_spec: dict = Field(default_factory=dict)

    @field_validator("reproducibility_spec")
    @classmethod
    def validate_spec(cls, v: dict) -> dict:
        return _validate_attrs(v)


class EvidenceRead(BaseModel):
    """Evidence record as persisted (read-only from client perspective)."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    entity_id: uuid.UUID | None
    source_plugin: str
    query: str
    response_hash: str
    response_uri: str
    response_bytes: int
    response_content_type: str | None
    timestamp: datetime
    reproducibility_spec: dict
    created_by: uuid.UUID | None
    # Presigned blob URL — injected at the router layer, not stored
    blob_url: str | None = None


class EvidenceList(BaseModel):
    """Paginated shell — `total` matters for audit ('ledger has N records')."""
    items: list[EvidenceRead]
    total: int
    limit: int
    offset: int
