"""Alert correlation / dedup columns on incidents.

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-05
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # correlation_key   — stable fingerprint used for the fast dedup prefilter
    # correlated_entities — {ips, users, hosts, service} used for entity overlap
    # alert_count       — how many raw alerts folded into this one incident
    # related_signals   — audit trail of folded alerts [{signal_id, at, reason}]
    # last_seen_at      — most recent folded alert (drives the correlation window)
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS correlation_key TEXT")
    op.execute(
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS correlated_entities JSONB "
        "DEFAULT '{}'::jsonb"
    )
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS alert_count INTEGER NOT NULL DEFAULT 1")
    op.execute(
        "ALTER TABLE incidents ADD COLUMN IF NOT EXISTS related_signals JSONB "
        "DEFAULT '[]'::jsonb"
    )
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ")
    op.execute("UPDATE incidents SET last_seen_at = created_at WHERE last_seen_at IS NULL")

    # Fast prefilter: open incidents by fingerprint, most-recent first.
    op.create_index(
        "idx_incidents_correlation",
        "incidents",
        ["correlation_key", "status", sa.text("last_seen_at DESC")],
    )
    op.create_index(
        "idx_incidents_open_recent",
        "incidents",
        ["status", sa.text("last_seen_at DESC")],
    )
    # GIN index enables JSONB containment queries on entities if needed later.
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_entities "
        "ON incidents USING GIN (correlated_entities)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_incidents_entities")
    op.drop_index("idx_incidents_open_recent", table_name="incidents")
    op.drop_index("idx_incidents_correlation", table_name="incidents")
    for col in (
        "correlation_key",
        "correlated_entities",
        "alert_count",
        "related_signals",
        "last_seen_at",
    ):
        op.execute(f"ALTER TABLE incidents DROP COLUMN IF EXISTS {col}")
