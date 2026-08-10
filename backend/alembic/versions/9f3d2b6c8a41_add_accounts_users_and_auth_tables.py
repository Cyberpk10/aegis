"""add accounts, users, and auth tables; scope existing data to accounts

Revision ID: 9f3d2b6c8a41
Revises: f4a2c9d18e6b
Create Date: 2026-08-10 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import Text
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '9f3d2b6c8a41'
down_revision: Union[str, Sequence[str], None] = 'f4a2c9d18e6b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=Text()), 'postgresql')

# Fixed UUID for the one-time bootstrap account created by this migration — every
# pre-existing row (across all environments that already have data; production's cases/
# incidents tables are confirmed empty at the time of writing) is backfilled to it. New
# signups create their own real accounts going forward.
_BOOTSTRAP_ACCOUNT_ID = '199d217d-b03b-4cf3-8d93-2b6b0b3c8f59'


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'accounts',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )

    op.execute(
        f"INSERT INTO accounts (id, name, created_at) "
        f"VALUES ('{_BOOTSTRAP_ACCOUNT_ID}', 'Bootstrap Account', now())"
    )

    op.create_table(
        'users',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('password_hash', sa.String(), nullable=False),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
    )

    op.create_table(
        'refresh_tokens',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('replaced_by_id', sa.Uuid(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['replaced_by_id'], ['refresh_tokens.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )

    op.create_table(
        'password_reset_tokens',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )

    op.create_table(
        'invites',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('token_hash', sa.String(), nullable=False),
        sa.Column('invited_by_user_id', sa.Uuid(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('accepted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['invited_by_user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )

    op.create_table(
        'audit_log_entries',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('account_id', sa.Uuid(), nullable=True),
        sa.Column('user_id', sa.Uuid(), nullable=True),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('detail', _JSON, nullable=True),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['account_id'], ['accounts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )

    # account_id added to every existing table, backfilled to the bootstrap account via
    # server_default (same "NOT NULL column on a table that may already have rows" pattern
    # as f4a2c9d18e6b's `channel` column), then the default is dropped so all future rows
    # must set it explicitly (matching the ORM columns, which have no Python-side default).
    scoped_tables = [
        'cases', 'labels', 'audit_reports', 'remediation_actions',
        'training_recommendations', 'incidents', 'events', 'actor_baselines',
    ]
    for table in scoped_tables:
        op.add_column(
            table,
            sa.Column('account_id', sa.Uuid(), nullable=False, server_default=_BOOTSTRAP_ACCOUNT_ID),
        )
        op.create_foreign_key(
            f'fk_{table}_account_id_accounts', table, 'accounts', ['account_id'], ['id'],
            ondelete='CASCADE',
        )
        op.alter_column(table, 'account_id', server_default=None)

    # recipient/actor uniqueness becomes per-account — two accounts can share an identifier.
    op.drop_constraint('training_recommendations_recipient_key', 'training_recommendations', type_='unique')
    op.create_unique_constraint(
        'uq_training_recommendations_account_recipient', 'training_recommendations',
        ['account_id', 'recipient'],
    )
    op.drop_constraint('actor_baselines_actor_key', 'actor_baselines', type_='unique')
    op.create_unique_constraint(
        'uq_actor_baselines_account_actor', 'actor_baselines', ['account_id', 'actor'],
    )

    # autonomy_policies/autonomy_actions: tenant_id (a stub string, e.g. "default") is not a
    # valid account UUID, so this can't be a straight rename — add account_id, backfill,
    # then drop tenant_id.
    for table, unique in (('autonomy_policies', True), ('autonomy_actions', False)):
        op.add_column(
            table,
            sa.Column('account_id', sa.Uuid(), nullable=False, server_default=_BOOTSTRAP_ACCOUNT_ID),
        )
        op.create_foreign_key(
            f'fk_{table}_account_id_accounts', table, 'accounts', ['account_id'], ['id'],
            ondelete='CASCADE',
        )
        op.alter_column(table, 'account_id', server_default=None)
        op.drop_constraint(f'{table}_tenant_id_key', table, type_='unique') if unique else None
        op.drop_column(table, 'tenant_id')
        if unique:
            op.create_unique_constraint('uq_autonomy_policies_account_id', table, ['account_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.add_column('autonomy_actions', sa.Column('tenant_id', sa.String(), nullable=True))
    op.execute("UPDATE autonomy_actions SET tenant_id = 'default'")
    op.alter_column('autonomy_actions', 'tenant_id', nullable=False)
    op.drop_constraint('fk_autonomy_actions_account_id_accounts', 'autonomy_actions', type_='foreignkey')
    op.drop_column('autonomy_actions', 'account_id')

    op.drop_constraint('uq_autonomy_policies_account_id', 'autonomy_policies', type_='unique')
    op.add_column('autonomy_policies', sa.Column('tenant_id', sa.String(), nullable=True))
    op.execute("UPDATE autonomy_policies SET tenant_id = 'default'")
    op.alter_column('autonomy_policies', 'tenant_id', nullable=False)
    op.create_unique_constraint('autonomy_policies_tenant_id_key', 'autonomy_policies', ['tenant_id'])
    op.drop_constraint('fk_autonomy_policies_account_id_accounts', 'autonomy_policies', type_='foreignkey')
    op.drop_column('autonomy_policies', 'account_id')

    op.drop_constraint('uq_actor_baselines_account_actor', 'actor_baselines', type_='unique')
    op.create_unique_constraint('actor_baselines_actor_key', 'actor_baselines', ['actor'])
    op.drop_constraint('uq_training_recommendations_account_recipient', 'training_recommendations', type_='unique')
    op.create_unique_constraint(
        'training_recommendations_recipient_key', 'training_recommendations', ['recipient'],
    )

    scoped_tables = [
        'cases', 'labels', 'audit_reports', 'remediation_actions',
        'training_recommendations', 'incidents', 'events', 'actor_baselines',
    ]
    for table in scoped_tables:
        op.drop_constraint(f'fk_{table}_account_id_accounts', table, type_='foreignkey')
        op.drop_column(table, 'account_id')

    op.drop_table('audit_log_entries')
    op.drop_table('invites')
    op.drop_table('password_reset_tokens')
    op.drop_table('refresh_tokens')
    op.drop_table('users')
    op.drop_table('accounts')
