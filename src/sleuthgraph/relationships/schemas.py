"""Pydantic schemas for Relationship."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sleuthgraph.relationships.types import RelationshipType
from sleuthgraph.graph.validators import _validate_attrs


class RelationshipCreate(BaseModel):
    src_entity_id: uuid.UUID
    dst_entity_id: uuid.UUID
    rel_type: RelationshipType
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_plugin: str | None = Field(default=None, max_length=128)
    attrs: dict = Field(default_factory=dict)

    @field_validator("attrs")
    @classmethod
    def validate_attrs(cls, v: dict) -> dict:
        return _validate_attrs(v)


# NO RelationshipUpdate — relationships are immutable after create.
# Edits happen via delete + recreate (chain of custody).


class RelationshipRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    src_entity_id: uuid.UUID
    dst_entity_id: uuid.UUID
    rel_type: RelationshipType
    confidence: float
    source_plugin: str | None
    attrs: dict
    created_by: uuid.UUID | None
    created_at: datetime
