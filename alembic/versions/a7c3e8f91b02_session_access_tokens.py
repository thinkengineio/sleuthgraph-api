"""session: access tokens for DB-backed session revocation

Revision ID: a7c3e8f91b02
Revises: 315b7e1f6707
Create Date: 2026-05-17 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from fastapi_users_db_sqlalchemy.generics import GUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a7c3e8f91b02"
down_revision: str | Sequence[str] | None = "315b7e1f6707"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create accesstoken table for DB-backed session revocation."""
    op.create_table(
        "accesstoken",
        sa.Column("token", sa.String(length=43), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", GUID(), nullable=False),
        sa.PrimaryKeyConstraint("token"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="cascade"),
    )
    op.create_index(op.f("ix_accesstoken_created_at"), "accesstoken", ["created_at"])


def downgrade() -> None:
    """Drop accesstoken table."""
    op.drop_index(op.f("ix_accesstoken_created_at"), table_name="accesstoken")
    op.drop_table("accesstoken")
