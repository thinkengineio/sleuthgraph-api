"""baseline (no models yet)

Revision ID: 43a9bd17439e
Revises:
Create Date: 2026-04-17 16:38:32.958853

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "43a9bd17439e"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
