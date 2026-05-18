"""credentials table for BYOK plugin keys

Revision ID: a1b2c3d4e5f6
Revises: 315b7e1f6707
Create Date: 2026-05-16 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from fastapi_users_db_sqlalchemy.generics import GUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | Sequence[str] | None = "315b7e1f6707"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create credentials table."""
    op.create_table(
        "credentials",
        sa.Column("id", GUID(), nullable=False),
        sa.Column("user_id", GUID(), nullable=False),
        sa.Column("plugin_name", sa.String(length=128), nullable=False),
        sa.Column("encrypted_key", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "plugin_name"),
    )


def downgrade() -> None:
    """Drop credentials table."""
    op.drop_table("credentials")
