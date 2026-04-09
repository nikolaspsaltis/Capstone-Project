"""Hash-chain columns on audit_logs

Revision ID: 0006
Revises: 0005_add_api_key_scopes
Create Date: 2026-04-05
"""

import sqlalchemy as sa

from alembic import op

revision = "0006"
down_revision = "0005_add_api_key_scopes"


def upgrade():
    op.add_column("audit_logs", sa.Column("prev_hash", sa.String(64), nullable=True))
    op.add_column(
        "audit_logs",
        sa.Column(
            "record_hash",
            sa.String(64),
            nullable=False,
            server_default="0" * 64,
        ),
    )


def downgrade():
    op.drop_column("audit_logs", "record_hash")
    op.drop_column("audit_logs", "prev_hash")
