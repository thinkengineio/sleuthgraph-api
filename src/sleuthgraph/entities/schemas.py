"""Pydantic schemas for Entity."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from sleuthgraph.entities.types import EntityType


class EntityCreate(BaseModel):
    type: EntityType
    label: str = Field(min_length=1, max_length=512)
    attrs: dict = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class EntityUpdate(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=512)
    attrs: dict | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class EntityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    type: EntityType
    label: str
    attrs: dict
    confidence: float
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
