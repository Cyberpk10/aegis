"""add accounts.inbound_token and cases.content_hash (M8 Stage 3 email forwarding intake)

Revision ID: b4fac8fead3c
Revises: 9f3d2b6c8a41
Create Date: 2026-08-17 00:00:00.000000

"""
import secrets
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b4fac8fead3c'
down_revision: Union[str, Sequence[str], None] = '9f3d2b6c8a41'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Mirrors app.auth.security.generate_inbound_token() — deliberately duplicated rather than
# imported, so this migration keeps working unchanged even if that function's alphabet/length
# ever changes later (migrations are a historical record, not a live call site).
_INBOUND_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_INBOUND_TOKEN_LENGTH = 12


def _generate_inbound_token() -> str:
    return "".join(secrets.choice(_INBOUND_TOKEN_ALPHABET) for _ in range(_INBOUND_TOKEN_LENGTH))


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('accounts', sa.Column('inbound_token', sa.String(), nullable=True))

    # Each existing account needs a *different* random token, so this can't be a single
    # server_default backfill (unlike the account_id backfill in 9f3d2b6c8a41) — loop over
    # rows and UPDATE each individually.
    conn = op.get_bind()
    account_ids = [row[0] for row in conn.execute(sa.text("SELECT id FROM accounts")).fetchall()]
    for account_id in account_ids:
        conn.execute(
            sa.text("UPDATE accounts SET inbound_token = :token WHERE id = :id"),
            {"token": _generate_inbound_token(), "id": account_id},
        )

    op.alter_column('accounts', 'inbound_token', nullable=False)
    op.create_unique_constraint('uq_accounts_inbound_token', 'accounts', ['inbound_token'])

    op.add_column('cases', sa.Column('content_hash', sa.String(), nullable=True))
    op.create_index('ix_cases_account_content_hash', 'cases', ['account_id', 'content_hash'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_cases_account_content_hash', table_name='cases')
    op.drop_column('cases', 'content_hash')

    op.drop_constraint('uq_accounts_inbound_token', 'accounts', type_='unique')
    op.drop_column('accounts', 'inbound_token')
