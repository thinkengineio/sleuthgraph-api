"""AccessToken model for DB-backed session revocation.

Overrides the default fastapi-users FK target from ``user.id`` to
``users.id`` to match our User model's ``__tablename__``.
"""

import uuid

from fastapi_users_db_sqlalchemy.access_token import SQLAlchemyBaseAccessTokenTable
from fastapi_users_db_sqlalchemy.generics import GUID
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, declared_attr, mapped_column

from sleuthgraph.db import Base


class AccessToken(SQLAlchemyBaseAccessTokenTable[uuid.UUID], Base):
    __tablename__ = "accesstoken"

    @declared_attr
    def user_id(cls) -> Mapped[GUID]:
        return mapped_column(
            GUID, ForeignKey("users.id", ondelete="cascade"), nullable=False
        )
