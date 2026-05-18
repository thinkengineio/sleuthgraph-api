"""Pydantic schemas for plugins: PluginInfo (registry listing) + PluginRunRead."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from sleuthgraph.entities.types import EntityType


class PluginInfo(BaseModel):
    """Static plugin metadata for the /plugins listing."""

    name: str
    version: str
    entity_types_accepted: list[EntityType]
    entity_types_produced: list[EntityType]
    requires_credentials: bool


class RunPluginRequest(BaseModel):
    """Typed request body for POST /cases/{id}/plugins/{name}/run."""

    input_entity_id: uuid.UUID


class PluginRunRead(BaseModel):
    """Audit row read shape for /plugins/runs listings."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    case_id: uuid.UUID
    input_entity_id: uuid.UUID | None
    plugin_name: str
    plugin_version: str
    started_at: datetime
    finished_at: datetime | None
    status: str
    error_message: str | None
    entities_created_count: int
    relationships_created_count: int
    evidence_count: int
    created_by: uuid.UUID | None


class PluginRunList(BaseModel):
    items: list[PluginRunRead]
    total: int
    limit: int
    offset: int
