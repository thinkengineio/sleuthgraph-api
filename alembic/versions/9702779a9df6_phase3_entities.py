"""phase3: entities

Revision ID: 9702779a9df6
Revises: e8b9f7244250
Create Date: 2026-04-18 12:08:05.851038

"""

from collections.abc import Sequence

import sqlalchemy as sa
from fastapi_users_db_sqlalchemy.generics import GUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9702779a9df6"
down_revision: str | Sequence[str] | None = "e8b9f7244250"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "entities",
        sa.Column("id", GUID(), nullable=False),
        sa.Column("case_id", GUID(), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=512), nullable=False),
        sa.Column("attrs", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("created_by", GUID(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_entities_case_id"), "entities", ["case_id"], unique=False)
    op.create_index(op.f("ix_entities_type"), "entities", ["type"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_entities_type"), table_name="entities")
    op.drop_index(op.f("ix_entities_case_id"), table_name="entities")
    op.drop_table("entities")
