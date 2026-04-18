"""Pydantic schemas for the Case resource."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


CaseStatus = Literal["active", "archived"]


class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    tags: list[str] = Field(default_factory=list)


class CaseUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    status: CaseStatus | None = None
    tags: list[str] | None = None


class CaseRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    owner_id: uuid.UUID | None
    name: str
    status: CaseStatus
    tags: list[str]
    created_at: datetime
    updated_at: datetime
