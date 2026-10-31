"""SQLAlchemy ORM models.

Mirrors the Pydantic schemas in `app.core.schemas` but is a separate layer on
purpose: Pydantic models are the wire/validation contract between
components, these are the persistence contract. `repository.py` translates
between them. JSON columns are used for nested/structured data
(assessment_policy, evidence raw_data, tool_executions, etc.) rather than
normalising everything, matching the PRD's emphasis on PostgreSQL as shared
*state*, not a fully relational schema for every nested shape.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


class Base(DeclarativeBase):
    pass


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class AssessmentRecord(Base):
    __tablename__ = "assessments"

    assessment_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scope_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), default="created")
    assessment_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    network_graph_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    binaries_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    assets: Mapped[list["AssetRecord"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    binaries: Mapped[list["BinaryAssetRecord"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    tasks: Mapped[list["AgentTaskRecord"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    findings: Mapped[list["FindingRecord"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")
    logs: Mapped[list["ExecutionLogRecord"]] = relationship(back_populates="assessment", cascade="all, delete-orphan")


class ScopePolicyRecord(Base):
    """Historical/audit copy of the policy in force at assessment creation,
    kept separate from `AssessmentRecord.assessment_policy` (the live value)
    so a later policy change doesn't rewrite assessment history."""
    __tablename__ = "scope_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(String(64), ForeignKey("assessments.assessment_id"), index=True)
    policy: Mapped[dict] = mapped_column(JSON)
    recorded_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class NetworkGraphRecord(Base):
    """The normalised graph produced by the Network Graph Adapter, stored
    once per assessment so re-runs of later pipeline stages don't need to
    re-parse the source file."""
    __tablename__ = "network_graphs"

    assessment_id: Mapped[str] = mapped_column(String(64), ForeignKey("assessments.assessment_id"), primary_key=True)
    scope_id: Mapped[str] = mapped_column(String(64))
    generated_by: Mapped[str] = mapped_column(String(128), default="network_probe")
    raw_source_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    normalised_graph: Mapped[dict] = mapped_column(JSON)  # full NetworkGraph.model_dump()
    loaded_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AssetRecord(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[str] = mapped_column(String(128), index=True)  # original graph ID, preserved verbatim
    assessment_id: Mapped[str] = mapped_column(String(64), ForeignKey("assessments.assessment_id"), index=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(32), default="host")
    discovery_source: Mapped[str] = mapped_column(String(32), default="graph_import")

    assessment: Mapped["AssessmentRecord"] = relationship(back_populates="assets")
    services: Mapped[list["ServiceRecord"]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class ServiceRecord(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    service_id: Mapped[str] = mapped_column(String(128), index=True)  # original graph ID, preserved verbatim
    asset_db_id: Mapped[int] = mapped_column(Integer, ForeignKey("assets.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)

    asset: Mapped["AssetRecord"] = relationship(back_populates="services")


class BinaryAssetRecord(Base):
    __tablename__ = "binaries"

    binary_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(String(64), ForeignKey("assessments.assessment_id"), index=True)
    file_name: Mapped[str] = mapped_column(String(255))
    file_path: Mapped[str] = mapped_column(String(512))
    file_hash: Mapped[str] = mapped_column(String(64))
    format: Mapped[str | None] = mapped_column(String(16), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(32), nullable=True)

    assessment: Mapped["AssessmentRecord"] = relationship(back_populates="binaries")


class AgentTaskRecord(Base):
    __tablename__ = "agent_tasks"

    task_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(String(64), ForeignKey("assessments.assessment_id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(64))
    task_type: Mapped[str] = mapped_column(String(64))
    input_data: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    output_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    parent_task_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    initiated_by: Mapped[str] = mapped_column(String(32), default="orchestrator")
    execution_method: Mapped[str | None] = mapped_column(String(256), nullable=True)
    evidence_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    verification_status: Mapped[str | None] = mapped_column(String(16), nullable=True)

    assessment: Mapped["AssessmentRecord"] = relationship(back_populates="tasks")


class FindingRecord(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(String(64), ForeignKey("assessments.assessment_id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    surface: Mapped[str] = mapped_column(String(16), index=True)
    asset_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    binary_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    service_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="suspected", index=True)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    ptes_phase: Mapped[str] = mapped_column(String(48))
    detection_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    affected_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    endpoint: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    function_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    function_address: Mapped[str | None] = mapped_column(String(32), nullable=True)
    verification_required: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    assessment: Mapped["AssessmentRecord"] = relationship(back_populates="findings")
    evidence: Mapped[list["EvidenceRecord"]] = relationship(back_populates="finding", cascade="all, delete-orphan")


class EvidenceRecord(Base):
    __tablename__ = "evidence"

    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_id: Mapped[str] = mapped_column(String(64), ForeignKey("findings.finding_id"), index=True)
    evidence_type: Mapped[str] = mapped_column(String(64))
    source_tool: Mapped[str] = mapped_column(String(64))
    storage_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    description: Mapped[str] = mapped_column(Text)
    raw_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    finding: Mapped["FindingRecord"] = relationship(back_populates="evidence")


class AttackPathRecord(Base):
    """One edge of the correlated attack-path graph (see
    app.analysis.attack_paths). Stored denormalised (source/target/relation)
    rather than as a blob so the report generator and any future API can
    query it directly."""
    __tablename__ = "attack_paths"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(String(64), ForeignKey("assessments.assessment_id"), index=True)
    source_node: Mapped[str] = mapped_column(String(128))
    target_node: Mapped[str] = mapped_column(String(128))
    relation: Mapped[str] = mapped_column(String(32))  # HOSTS|EXPOSES|CONNECTS_TO|AFFECTED_BY|POTENTIAL_ACCESS_RELATION|VERIFIED_TRANSITION
    evidence_backed: Mapped[bool] = mapped_column(default=False)
    finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)


class ExecutionLogRecord(Base):
    __tablename__ = "agent_execution_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(String(64), ForeignKey("assessments.assessment_id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(64))
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operation: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    allowed: Mapped[bool | None] = mapped_column(nullable=True)
    message: Mapped[str] = mapped_column(Text)
    level: Mapped[str] = mapped_column(String(16), default="info")
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    assessment: Mapped["AssessmentRecord"] = relationship(back_populates="logs")
