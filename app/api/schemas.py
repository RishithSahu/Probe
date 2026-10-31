"""HTTP request/response models for the FastAPI backend.

Kept separate from `app.core.schemas` (the inter-component data contract) —
these describe the wire shape of the API specifically, including fields
(like an optional client-supplied `assessment_id`) that don't belong in the
internal contract.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.core.schemas import AssessmentPolicy, AssessmentStatus, ExternalNetworkFinding, Finding


class BinaryInput(BaseModel):
    binary_id: str | None = Field(default=None, description="Generated if omitted.")
    file_path: str = Field(description="Path to an organiser-supplied binary under inputs/binaries/.")


class CreateAssessmentRequest(BaseModel):
    assessment_id: str | None = Field(default=None, description="Generated (ASSESSMENT-<uuid8>) if omitted.")
    scope_id: str
    assessment_policy: AssessmentPolicy = Field(default_factory=AssessmentPolicy)
    network_graph_path: str | None = Field(
        default=None, description="Path to the already-completed network graph JSON export."
    )
    binaries: list[BinaryInput] = Field(default_factory=list)
    run_immediately: bool = Field(
        default=True, description="If true, the Orchestrator pipeline runs as a background task right away."
    )


class CreateAssessmentResponse(BaseModel):
    assessment_id: str
    scope_id: str
    status: AssessmentStatus
    message: str


class AssessmentResponse(BaseModel):
    assessment_id: str
    scope_id: str
    status: str
    network_graph_ref: str | None
    binaries_ref: str | None
    created_at: datetime
    completed_at: datetime | None


class AgentTaskStatusResponse(BaseModel):
    task_id: str
    agent_id: str
    task_type: str
    status: str
    error_message: str | None
    started_at: datetime | None
    completed_at: datetime | None


class FindingsResponse(BaseModel):
    assessment_id: str
    count: int
    findings: list[Finding]


class ExternalFindingsRequest(BaseModel):
    findings: list[ExternalNetworkFinding]


class ExternalFindingsResponse(BaseModel):
    accepted: int
    finding_ids: list[str]


class ReportResponse(BaseModel):
    assessment_id: str
    json_report: dict
