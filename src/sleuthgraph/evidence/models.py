"""Evidence ORM model — append-only audit trail."""

import uuid
from datetime import datetime

from fastapi_users_db_sqlalchemy.generics import GUID
from sqlalchemy import JSON, BigInteger, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from sleuthgraph.auth.models import User  # noqa: F401
from sleuthgraph.cases.models import Case  # noqa: F401
from sleuthgraph.db import Base
from sleuthgraph.entities.models import Entity  # noqa: F401


class Evidence(Base):
    """A piece of evidence tied to a case and optionally an entity.

    APPEND-ONLY: no updated_at, no deleted_at. Outlives soft-deleted cases;
    only removed when the parent case is hard-deleted (FK CASCADE).
    """

    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    entity_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("entities.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    source_plugin: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    query: Mapped[str] = mapped_column(String(1024), nullable=False)
    response_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    response_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    response_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    response_content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False,
    )
    reproducibility_spec: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
