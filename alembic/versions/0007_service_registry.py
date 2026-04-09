"""Service registry table

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa

from alembic import op

revision = "0007"
down_revision = "0006"


def upgrade():
    op.create_table(
        "service_registry",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("service_id", sa.String(64), unique=True, nullable=False),
        sa.Column("audience", sa.String(256), unique=True, nullable=False),
        sa.Column("allowed_callers", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, default=True),
        sa.Column("created_at", sa.DateTime, default=sa.func.now()),
    )


def downgrade():
    op.drop_table("service_registry")
