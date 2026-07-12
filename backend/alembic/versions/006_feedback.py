"""Add triage_feedback table.

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-11
"""
from __future__ import annotations

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS triage_feedback (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            given_by TEXT NOT NULL,
            ai_verdict TEXT,
            human_verdict TEXT NOT NULL CHECK (human_verdict IN ('TRUE_POSITIVE','FALSE_POSITIVE','BENIGN_ANOMALY','NEEDS_HUMAN')),
            ai_severity TEXT,
            human_severity TEXT,
            note TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE(incident_id, given_by)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS triage_feedback")
