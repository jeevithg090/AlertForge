"""${message}

Revision ID: 0001
Revises:
Create Date: 2025-07-02
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.create_table(
        "incidents",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "signal_id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False, unique=True
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("resolved_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("category", sa.String(30), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="INGESTED"),
        sa.Column("source", sa.String(30), nullable=False),
        sa.Column("affected_service", sa.String(255), nullable=False),
        sa.Column("affected_hosts", sa.dialects.postgresql.ARRAY(sa.Text), server_default="{}"),
        sa.Column("alert_message", sa.Text, nullable=False),
        sa.Column("triage_result", sa.dialects.postgresql.JSONB),
        sa.Column("investigation_finding", sa.dialects.postgresql.JSONB),
        sa.Column("remediation_plan", sa.dialects.postgresql.JSONB),
        sa.Column("pir_report", sa.Text),
        sa.Column("is_false_positive", sa.Boolean, server_default=sa.text("FALSE")),
        sa.Column("auto_resolved", sa.Boolean, server_default=sa.text("FALSE")),
        sa.Column("mttr_seconds", sa.Integer),
        sa.Column("qwen_tokens_used", sa.Integer, server_default="0"),
        sa.CheckConstraint(
            "status IN ('INGESTED','TRIAGING','INVESTIGATING','PLANNING',"
            "'AWAITING_APPROVAL','EXECUTING','RESOLVED','DISMISSED','ESCALATED')",
            name="valid_status",
        ),
    )

    op.create_table(
        "remediation_steps",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "incident_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("step_number", sa.Integer, nullable=False),
        sa.Column("action_type", sa.String(50), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="PENDING"),
        sa.Column("risk_level", sa.String(25), nullable=False),
        sa.Column("requires_approval", sa.Boolean, nullable=False, server_default=sa.text("FALSE")),
        sa.Column("approved_by", sa.String(255)),
        sa.Column("approved_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("executed_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("execution_output", sa.Text),
        sa.Column("validation_passed", sa.Boolean),
        sa.Column("was_rolled_back", sa.Boolean, server_default=sa.text("FALSE")),
        sa.Column("rollback_output", sa.Text),
        sa.Column("rollback_procedure", sa.Text),
        sa.Column("validation_check", sa.Text),
        sa.Column("tool_to_invoke", sa.String(100)),
        sa.Column("tool_parameters", sa.dialects.postgresql.JSONB),
        sa.UniqueConstraint("incident_id", "step_number"),
    )

    op.create_table(
        "audit_log",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "incident_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("incidents.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "timestamp",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("actor", sa.String(100), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("details", sa.dialects.postgresql.JSONB),
        sa.Column("ip_address", sa.dialects.postgresql.INET),
        sa.Column("qwen_model", sa.String(50)),
        sa.Column("qwen_input_tokens", sa.Integer),
        sa.Column("qwen_output_tokens", sa.Integer),
        sa.Column("qwen_thinking_tokens", sa.Integer),
    )

    op.create_table(
        "alert_sources",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("source_type", sa.String(30), nullable=False),
        sa.Column("is_active", sa.Boolean, server_default=sa.text("TRUE")),
        sa.Column("webhook_secret", sa.String(255)),
        sa.Column("config", sa.dialects.postgresql.JSONB, server_default=sa.text("'{}'::jsonb")),
    )

    op.create_table(
        "runbooks",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("category", sa.String(100)),
        sa.Column("tags", sa.dialects.postgresql.ARRAY(sa.Text)),
        sa.Column("github_path", sa.String(1000)),
        sa.Column("last_indexed_at", sa.TIMESTAMP(timezone=True)),
        sa.Column("chroma_doc_id", sa.String(100), unique=True),
        sa.Column("content", sa.Text),
    )

    op.create_index("idx_incidents_status", "incidents", ["status"])
    op.create_index("idx_incidents_severity", "incidents", ["severity"])
    op.create_index("idx_incidents_created_at", "incidents", [sa.text("created_at DESC")])
    op.create_index("idx_incidents_service", "incidents", ["affected_service"])
    op.create_index("idx_audit_incident", "audit_log", ["incident_id", sa.text("timestamp DESC")])
    op.create_index("idx_audit_timestamp", "audit_log", [sa.text("timestamp DESC")])
    op.create_index("idx_steps_incident_status", "remediation_steps", ["incident_id", "status"])


def downgrade() -> None:
    op.drop_table("runbooks")
    op.drop_table("alert_sources")
    op.drop_table("audit_log")
    op.drop_table("remediation_steps")
    op.drop_table("incidents")
