"""add ml_probability and ml_model_version to cases

Revision ID: a1c9e3f7b2d4
Revises: dc4196bf57c8
Create Date: 2026-08-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'a1c9e3f7b2d4'
down_revision: Union[str, Sequence[str], None] = 'dc4196bf57c8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Nullable, mirroring analyst_narrative/analyst_model — populated only when
    # ENABLE_ML_CLASSIFIER was on and inference succeeded for a given case (M3).
    op.add_column('cases', sa.Column('ml_probability', sa.Float(), nullable=True))
    op.add_column('cases', sa.Column('ml_model_version', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cases', 'ml_model_version')
    op.drop_column('cases', 'ml_probability')
