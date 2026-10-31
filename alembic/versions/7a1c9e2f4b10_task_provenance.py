"""agent_tasks execution provenance

Revision ID: 7a1c9e2f4b10
Revises: 52b26ccce240
Create Date: 2026-11-01

Adds columns distinguishing orchestrator-dispatched task execution from any other origin, and tracking
parent/child task relationships and verification outcome -- see app/core/schemas.py::AgentTask.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "7a1c9e2f4b10"
down_revision = "52b26ccce240"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_tasks", sa.Column("parent_task_id", sa.String(128), nullable=True))
    op.create_index("ix_agent_tasks_parent_task_id", "agent_tasks", ["parent_task_id"])
    op.add_column("agent_tasks", sa.Column("initiated_by", sa.String(32), nullable=False, server_default="orchestrator"))
    op.add_column("agent_tasks", sa.Column("execution_method", sa.String(256), nullable=True))
    op.add_column("agent_tasks", sa.Column("evidence_ids", sa.JSON(), nullable=True))
    op.add_column("agent_tasks", sa.Column("verification_status", sa.String(16), nullable=True))


def downgrade() -> None:
    op.drop_column("agent_tasks", "verification_status")
    op.drop_column("agent_tasks", "evidence_ids")
    op.drop_column("agent_tasks", "execution_method")
    op.drop_column("agent_tasks", "initiated_by")
    op.drop_index("ix_agent_tasks_parent_task_id", table_name="agent_tasks")
    op.drop_column("agent_tasks", "parent_task_id")
