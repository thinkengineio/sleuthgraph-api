"""Auth ORM models."""

from fastapi_users_db_sqlalchemy import SQLAlchemyBaseUserTableUUID
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from sleuthgraph.db import Base


class User(SQLAlchemyBaseUserTableUUID, Base):
    __tablename__ = "users"

    name: Mapped[str | None] = mapped_column(String(length=255), nullable=True)
    oidc_sub: Mapped[str | None] = mapped_column(String(length=255), nullable=True, unique=True)
