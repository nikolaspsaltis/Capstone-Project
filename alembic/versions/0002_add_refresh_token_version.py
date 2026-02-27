"""add refresh token version column

Revision ID: 0002_add_refresh_token_version
Revises: 0001_initial_auth_schema
Create Date: 2026-02-27
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_add_refresh_token_version"
down_revision: Union[str, None] = "0001_initial_auth_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("refresh_token_version", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("refresh_token_version")
