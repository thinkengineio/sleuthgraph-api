"""OSINTPlugin base class + proposal types.

Plugins consume a single input entity and produce zero or more new entities,
typed relationships connecting them, and evidence records that audit the
plugin's HTTP interaction. The runner (Task 5.5) handles dedup + persistence —
plugins return "proposals" by value, not already-persisted rows.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from sleuthgraph.entities.types import EntityType
from sleuthgraph.relationships.types import RelationshipType

if TYPE_CHECKING:
    from sleuthgraph.entities.models import Entity


class EntityProposal(BaseModel):
    """An entity a plugin wants to create (may dedup to existing)."""

    # A stable in-batch reference so RelationshipProposal can point at it.
    # Plugins mint these (e.g. "sub-0", "sub-1"). Runner resolves to real UUIDs
    # during persistence.
    ref: str = Field(min_length=1, max_length=64)
    type: EntityType
    label: str = Field(min_length=1, max_length=512)
    attrs: dict = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class RelationshipProposal(BaseModel):
    """A relationship between two entities.

    Each endpoint can be either:
      - ``{"ref": "sub-0"}`` to point at an EntityProposal in the same batch,
      - or ``{"input": True}`` to point at the plugin's input entity.
    """

    src: dict
    dst: dict
    rel_type: RelationshipType
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_plugin: str | None = None  # Runner fills this with "<name>@<version>"
    attrs: dict = Field(default_factory=dict)


class EvidenceProposal(BaseModel):
    """A piece of evidence captured by the plugin during its query."""

    query: str = Field(min_length=1, max_length=1024)
    payload: bytes
    content_type: str | None = None
    reproducibility_spec: dict = Field(default_factory=dict)
    # Optional link back to the input entity so the ledger row carries entity_id
    link_to_input: bool = True

    model_config = ConfigDict(arbitrary_types_allowed=True)


class QueryResult(BaseModel):
    """What a plugin returns from query()."""

    entities: list[EntityProposal] = Field(default_factory=list)
    relationships: list[RelationshipProposal] = Field(default_factory=list)
    evidence: list[EvidenceProposal] = Field(default_factory=list)

    model_config = ConfigDict(arbitrary_types_allowed=True)


class PluginContext(BaseModel):
    """Per-call context passed to plugins by the runner."""

    case_id: str
    input_entity: object  # Entity ORM instance — untyped to avoid circular import
    http_client: httpx.AsyncClient

    model_config = ConfigDict(arbitrary_types_allowed=True)


class OSINTPlugin(ABC):
    """Base class all plugins extend.

    Subclasses set the 5 class attributes then implement ``query``.
    Example (simplified):

        class CrtShPlugin(OSINTPlugin):
            name = "crtsh"
            version = "0.1.0"
            entity_types_accepted = [EntityType.DOMAIN]
            entity_types_produced = [EntityType.DOMAIN]
            requires_credentials = False

            async def query(self, input_entity, credentials, context):
                ...
    """

    name: str = ""
    version: str = ""
    entity_types_accepted: list[EntityType] = []
    entity_types_produced: list[EntityType] = []
    requires_credentials: bool = False
    http_timeout_seconds: float = 30.0
    dispatch_mode: Literal["sync", "async"] = "sync"
    # When True, the plugin refuses to run on Community installs.  Set by
    # enterprise-only plugins shipped via the sleuthgraph-enterprise
    # distribution.  The runner enforces this via
    # ``licensing.assert_plugin_allowed`` before dispatch.
    premium: bool = False

    @abstractmethod
    async def query(
        self,
        input_entity: "Entity",
        credentials: dict | None,
        context: PluginContext,
    ) -> QueryResult:
        """Fetch external data and return proposals. No side effects."""
        ...

    @property
    def full_name(self) -> str:
        return f"{self.name}@{self.version}"
