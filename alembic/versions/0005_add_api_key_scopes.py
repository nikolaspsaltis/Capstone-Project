"""add api key scopes

Revision ID: 0005_add_api_key_scopes
Revises: 0004_add_audit_logs
Create Date: 2026-03-03
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005_add_api_key_scopes"
down_revision: Union[str, None] = "0004_add_audit_logs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "api_keys",
        sa.Column("scopes", sa.String(), nullable=False, server_default="data:read"),
    )


def downgrade() -> None:
    with op.batch_alter_table("api_keys") as batch_op:
        batch_op.drop_column("scopes")
