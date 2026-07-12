"""Tamper-evident audit log: monotonic seq + hash chain.

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-06
"""
from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # seq gives a total order for the chain; prev_hash/entry_hash form the chain
    # (each entry hashes the previous entry's hash + its own canonical content,
    # so any insert/edit/delete/reorder is detectable).
    op.execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS seq BIGSERIAL")
    op.execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS prev_hash TEXT")
    op.execute("ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS entry_hash TEXT")
    op.create_index("idx_audit_seq", "audit_log", ["seq"])


def downgrade() -> None:
    op.drop_index("idx_audit_seq", table_name="audit_log")
    for col in ("seq", "prev_hash", "entry_hash"):
        op.execute(f"ALTER TABLE audit_log DROP COLUMN IF EXISTS {col}")
