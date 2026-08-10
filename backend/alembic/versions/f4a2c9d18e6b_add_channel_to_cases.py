"""add channel to cases

Revision ID: f4a2c9d18e6b
Revises: 17511e53aede
Create Date: 2026-08-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'f4a2c9d18e6b'
down_revision: Union[str, Sequence[str], None] = '17511e53aede'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # server_default so this NOT NULL column can be added to a table that may already have
    # rows — every pre-existing case is an email case.
    op.add_column(
        'cases',
        sa.Column('channel', sa.String(), nullable=False, server_default='email'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cases', 'channel')
