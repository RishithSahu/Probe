"""agent_tasks.task_fingerprint

Revision ID: 9b2a7f1e3c44
Revises: 7a1c9e2f4b10
Create Date: 2026-11-01

task_id became a bounded hash (app/orchestrator/task_ids.py::make_task_id) because the old concatenated
ids (assessment_id + service_id + credential_ref, etc.) routinely exceeded the column's String(64) limit.
This column keeps the full, readable string the hash was derived from.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "9b2a7f1e3c44"
down_revision = "7a1c9e2f4b10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_tasks", sa.Column("task_fingerprint", sa.Text(), nullable=True))
    op.create_index("ix_agent_tasks_task_fingerprint", "agent_tasks", ["task_fingerprint"])


def downgrade() -> None:
    op.drop_index("ix_agent_tasks_task_fingerprint", table_name="agent_tasks")
    op.drop_column("agent_tasks", "task_fingerprint")
