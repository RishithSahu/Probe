"""agent_tasks reservation fencing token

Revision ID: 9c3fa1e7b204
Revises: 7a1c9e2f4b10
Create Date: 2026-11-01

Adds reservation_token: a fresh, random value minted by repository.try_reserve_task() on every successful
claim/reclaim of a task_id. A concurrent scheduler's final write (repository.try_complete_task) only
succeeds if the token it was given still matches what is currently on the row -- so a thread abandoned by
run_concurrently()'s timeout (Python cannot force-kill a running thread) that finishes LATER, after a retry
has already reclaimed the same task_id under a new token, can no longer silently overwrite that retry's
result with its own stale one. See app/orchestrator/autonomous_loop.py and app/database/repository.py.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "9c3fa1e7b204"
down_revision = "7a1c9e2f4b10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("agent_tasks", sa.Column("reservation_token", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("agent_tasks", "reservation_token")
