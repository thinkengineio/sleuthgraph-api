"""PluginRun ORM model — audit trail of plugin executions."""

import uuid
from datetime import datetime

from fastapi_users_db_sqlalchemy.generics import GUID
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from sleuthgraph.db import Base


class PluginRun(Base):
    """Audit row for a single plugin execution.

    Lifecycle: row created with status=running on dispatch; updated ONCE with
    final status (succeeded/failed), counts, finished_at. No further mutation.
    """

    __tablename__ = "plugin_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    input_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("entities.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    plugin_name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    plugin_version: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="running",
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    entities_created_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    relationships_created_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
