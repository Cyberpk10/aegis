"""add graph_integrations table (M6 Stage 2 real Microsoft Graph connector)

Revision ID: dc4196bf57c8
Revises: b4fac8fead3c
Create Date: 2026-08-24 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'dc4196bf57c8'
down_revision: Union[str, Sequence[str], None] = 'b4fac8fead3c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'graph_integrations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.String(), nullable=False),
        sa.Column('connected_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('account_id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('graph_integrations')
