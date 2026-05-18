"""Pydantic schemas for Evidence — append-only, so no Update type."""

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sleuthgraph.graph.validators import _validate_attrs

# Lowercase identifier: starts with a letter, then letters/digits/underscores/hyphens,
# optionally followed by @<semver> (e.g. crtsh@0.1.0).  Matches all registered
# plugin full_name values plus bare names and "manual".  Avoids importing the
# plugin registry (which pulls network/cred deps) at schema-validation time.
_SOURCE_PLUGIN_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}(@[0-9][0-9a-z._-]{0,31})?$")


class EvidenceCreate(BaseModel):
    """Evidence creation payload.

    Server computes response_hash, response_uri, response_bytes, timestamp.
    Client only provides what the evidence is ABOUT.
    """
    entity_id: uuid.UUID | None = None
    source_plugin: str = Field(default="manual", min_length=1, max_length=96)
    query: str = Field(min_length=1, max_length=1024)
    reproducibility_spec: dict = Field(default_factory=dict)

    @field_validator("source_plugin")
    @classmethod
    def validate_source_plugin(cls, v: str) -> str:
        if not _SOURCE_PLUGIN_RE.match(v):
            raise ValueError(
                f"source_plugin {v!r} must match "
                f"^[a-z][a-z0-9_-]{{0,63}}(@[0-9][0-9a-z._-]{{0,31}})?$"
            )
        return v

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
