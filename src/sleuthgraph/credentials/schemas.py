"""Pydantic schemas for BYOK credentials."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CredentialCreate(BaseModel):
    """Body for storing a new API key."""

    api_key: str = Field(min_length=1, max_length=4096)


class CredentialRead(BaseModel):
    """Read shape: exposes plugin name + timestamp, never the key."""

    model_config = ConfigDict(from_attributes=True)

    plugin_name: str
    created_at: datetime
