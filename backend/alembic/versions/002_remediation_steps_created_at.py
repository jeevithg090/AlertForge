"""Add created_at to remediation_steps + index for the HITL sweeper.

Revision ID: 0002
Revises: 0001
Create Date: 2025-07-03
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add created_at column to remediation_steps (missing from 0001) so
    # list_pending_steps' ORDER BY created_at works and the HITL auto-approve
    # sweeper can compute age.
    op.execute(
        "ALTER TABLE remediation_steps "
        "ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
    )
    op.create_index(
        "idx_steps_status_created",
        "remediation_steps",
        ["status", sa.text("created_at")],
    )


def downgrade() -> None:
    op.drop_index("idx_steps_status_created", table_name="remediation_steps")
    op.execute("ALTER TABLE remediation_steps DROP COLUMN IF EXISTS created_at")