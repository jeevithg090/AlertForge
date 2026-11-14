"""Add operators table and second_approver column to remediation_steps.

Revision ID: 0005
Revises: 0004
Create Date: 2026-07-11
"""

from __future__ import annotations

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS operators (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            email TEXT UNIQUE NOT NULL,
            display_name TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('viewer','analyst','approver','admin')),
            is_active BOOL DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """)
    op.execute("""
        ALTER TABLE remediation_steps
        ADD COLUMN IF NOT EXISTS second_approver TEXT
    """)


def downgrade() -> None:
    op.execute("ALTER TABLE remediation_steps DROP COLUMN IF EXISTS second_approver")
    op.execute("DROP TABLE IF EXISTS operators")
