"""findings per-finding verification fields

Revision ID: c4d8e91a7f02
Revises: 9b2a7f1e3c44
Create Date: 2026-11-01

Verification was previously only recorded on AgentTask (one status for every finding that task produced).
A task with three findings can have one verified, one suspected and one inconclusive -- this adds the
fields needed to say so per finding, restored by repository.finding_to_schema.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "c4d8e91a7f02"
down_revision = "9b2a7f1e3c44"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("verification_state", sa.String(16), nullable=True))
    op.add_column("findings", sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("findings", sa.Column("verifier", sa.String(128), nullable=True))
    op.add_column("findings", sa.Column("verification_evidence_refs", sa.JSON(), nullable=True))
    op.add_column("findings", sa.Column("verification_explanation", sa.Text(), nullable=True))
    op.add_column("findings", sa.Column("evidence_integrity_hash", sa.String(64), nullable=True))


def downgrade() -> None:
    for col in ("evidence_integrity_hash", "verification_explanation", "verification_evidence_refs",
               "verifier", "verified_at", "verification_state"):
        op.drop_column("findings", col)
