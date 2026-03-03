"""add audit logs table

Revision ID: 0004_add_audit_logs
Revises: 0003_auth_depth_features
Create Date: 2026-03-02
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_add_audit_logs"
down_revision: Union[str, None] = "0003_auth_depth_features"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("actor_username", sa.String(), nullable=True),
        sa.Column("actor_role", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("target_username", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_audit_logs_actor_username"),
        "audit_logs",
        ["actor_username"],
        unique=False,
    )
    op.create_index(op.f("ix_audit_logs_action"), "audit_logs", ["action"], unique=False)
    op.create_index(op.f("ix_audit_logs_created_at"), "audit_logs", ["created_at"], unique=False)
    op.create_index(op.f("ix_audit_logs_ip_address"), "audit_logs", ["ip_address"], unique=False)
    op.create_index(
        op.f("ix_audit_logs_target_username"),
        "audit_logs",
        ["target_username"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_audit_logs_target_username"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_ip_address"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_created_at"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_action"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_actor_username"), table_name="audit_logs")
    op.drop_table("audit_logs")
