"""Shared Pydantic data contracts used across the Orchestrator, both specialist
agents implemented here (Web Security, Binary Analysis), the external Network
Vulnerability Agent integration, and the persistence/reporting layers.

Every model carries `schema_version` so that a future incompatible change can
be detected by consumers (notably the teammate's independently-developed
Network Vulnerability Agent) instead of failing silently.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

SCHEMA_VERSION = "1.0.0"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Surface(str, enum.Enum):
    NETWORK = "network"
    WEB = "web"
    BINARY = "binary"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(str, enum.Enum):
    """A scanner alert is never automatically a confirmed vulnerability — it
    starts `suspected` and only moves to `confirmed` once evidence validation
    (see app/analysis/evidence_validator.py) is satisfied, or `rejected` if it
    is determined to be a false positive."""

    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class AssessmentStatus(str, enum.Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIALLY_COMPLETED = "partially_completed"


class AgentId(str, enum.Enum):
    # External: a separate, deeper Network Vulnerability Assessment Agent
    # integrated via POST /external-findings, and Probe's own lightweight
    # leads() signal (app/adapters/probe_leads.py) — neither is this
    # project's own code.
    NETWORK_VULNERABILITY = "network_vulnerability_agent"
    # This project's own agent (app/agents/network_vulnerability/): safe,
    # read-only protocol probes against services already in the graph.
    # Kept as a distinct identity from NETWORK_VULNERABILITY above so task
    # tracking/findings provenance never conflates "externally supplied"
    # with "this app's own checks" — they have different trust levels.
    NETWORK_VULNERABILITY_DETECTIVE = "network_vulnerability_detective"
    WEB_SECURITY = "web_security_agent"
    BINARY_ANALYSIS = "binary_analysis_agent"
    ORCHESTRATOR = "orchestrator"


class PtesPhase(str, enum.Enum):
    PRE_ENGAGEMENT = "pre_engagement_interactions"
    INTELLIGENCE_GATHERING = "intelligence_gathering"
    THREAT_MODELING = "threat_modeling"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


class DiscoverySource(str, enum.Enum):
    NETWORK_PROBE = "network_probe"  # teammate's existing discovery component
    GRAPH_IMPORT = "graph_import"
    MANUAL = "manual"


# ---------------------------------------------------------------------------
# Assessment policy / authorisation model (PRD Part 5 / Part 12)
# ---------------------------------------------------------------------------


class AssessmentPolicy(BaseModel):
    """Explicit, per-operation authorisation. Every permission defaults to the
    most conservative value (disabled) — enabling it is an explicit opt-in on
    assessment creation, never an implicit side effect of supplying inputs.

    `allow_network_discovery` exists for schema completeness (the external
    Network Vulnerability Agent's own authorisation) but this application
    never acts on it — it performs no discovery of its own.
    """

    schema_version: str = SCHEMA_VERSION

    allow_network_discovery: bool = Field(
        default=False, description="Authorisation for the external network probe only; unused here."
    )
    allow_network_service_assessment: bool = Field(
        default=False,
        description="Authorises the Network Vulnerability Detective's read-only protocol checks "
        "(app/agents/network_vulnerability/) against already-discovered services, and a separate, "
        "deeper external Network Vulnerability Agent's checks, should one be integrated.",
    )
    allow_ftp_anonymous_check: bool = Field(
        default=False,
        description="A single, well-known, non-invasive FTP login attempt using the 'anonymous' account "
        "specifically to test whether that FTP feature is enabled — not password guessing against an "
        "arbitrary account. Requires allow_network_service_assessment too; off by default.",
    )
    allow_web_crawling: bool = Field(
        default=False, description="Authorises Katana endpoint discovery against approved origins."
    )
    allow_passive_web_analysis: bool = Field(
        default=False, description="Authorises httpx fingerprinting + ZAP passive scanning."
    )
    allow_active_web_verification: bool = Field(
        default=False,
        description="Authorises ZAP active-scan rules. Must be explicitly enabled; "
        "never implied by crawling or passive-analysis permission.",
    )
    allow_binary_analysis: bool = Field(default=False)

    approved_web_origins: list[str] = Field(
        default_factory=list,
        description="Scheme+host[:port] origins the Web Agent and its crawler may touch, "
        "e.g. 'https://app.lab.local:8443'. Enforced by the Scope Guard on every request.",
    )
    approved_asset_ids: list[str] = Field(
        default_factory=list,
        description="If non-empty, restricts assessment to this subset of the graph's asset_ids.",
    )
    max_crawl_depth: int = Field(default=2, ge=0, le=10)
    max_crawl_requests_per_second: float = Field(default=2.0, gt=0, le=50)
    dry_run: bool = Field(
        default=True, description="When true, the Scope Guard logs intended tool invocations "
        "without executing them. Safe default for untrusted/first-run configurations."
    )


# ---------------------------------------------------------------------------
# Assessment / asset / service models (PRD Part 11)
# ---------------------------------------------------------------------------


class Assessment(BaseModel):
    schema_version: str = SCHEMA_VERSION
    assessment_id: str
    scope_id: str
    status: AssessmentStatus = AssessmentStatus.CREATED
    assessment_policy: AssessmentPolicy = Field(default_factory=AssessmentPolicy)
    network_graph_ref: str | None = Field(
        default=None, description="Path or URI to the completed network graph supplied for this assessment."
    )
    binaries_ref: str | None = Field(
        default=None, description="Directory or manifest reference for organiser-supplied binaries."
    )
    created_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime | None = None


class Asset(BaseModel):
    schema_version: str = SCHEMA_VERSION
    asset_id: str = Field(description="Original ID from the network graph — never regenerated.")
    ip: str | None = None
    hostname: str | None = None
    asset_type: str = Field(default="host")
    discovery_source: DiscoverySource = DiscoverySource.GRAPH_IMPORT


class Service(BaseModel):
    schema_version: str = SCHEMA_VERSION
    service_id: str = Field(description="Original ID from the network graph — never regenerated.")
    asset_id: str
    port: int = Field(ge=0, le=65535)
    protocol: str = Field(default="tcp")
    service_name: str | None = None
    version: str | None = None

    @property
    def is_http(self) -> bool:
        return self.service_name is not None and self.service_name.lower() in {"http", "https", "http-alt", "https-alt"}


class BinaryAsset(BaseModel):
    schema_version: str = SCHEMA_VERSION
    binary_id: str
    assessment_id: str
    file_name: str
    file_path: str
    file_hash: str = Field(description="SHA-256 of the file at ingestion time.")
    format: str | None = Field(default=None, description="ELF, PE, Mach-O, unknown, ...")
    architecture: str | None = None


# ---------------------------------------------------------------------------
# Evidence / Finding (PRD Part 11 / Part 7.3 / Part 8.3)
# ---------------------------------------------------------------------------


class Evidence(BaseModel):
    schema_version: str = SCHEMA_VERSION
    evidence_id: str
    finding_id: str
    evidence_type: str = Field(description="e.g. http_response, zap_alert, katana_endpoint, ghidra_function, string_match")
    source_tool: str
    storage_path: str | None = Field(default=None, description="Path under the evidence/ volume, if a raw artifact was saved.")
    description: str
    timestamp: datetime = Field(default_factory=_utcnow)
    raw_data: dict[str, Any] | None = Field(default=None, description="Small structured excerpt; large artifacts go to storage_path.")


class Finding(BaseModel):
    schema_version: str = SCHEMA_VERSION
    finding_id: str
    assessment_id: str
    agent_id: AgentId
    surface: Surface
    asset_id: str | None = None
    binary_id: str | None = None
    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    status: FindingStatus = FindingStatus.SUSPECTED
    evidence_refs: list[str] = Field(default_factory=list)
    remediation: str | None = None
    ptes_phase: PtesPhase = PtesPhase.VULNERABILITY_ANALYSIS
    detection_method: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)

    # --- Web-specific optional fields ---
    affected_url: str | None = None
    endpoint: str | None = None
    parameter: str | None = None

    # --- Binary-specific optional fields ---
    function_name: str | None = None
    function_address: str | None = None

    # --- Network-specific optional fields (teammate's agent) ---
    service_id: str | None = None

    verification_required: bool = Field(
        default=True, description="True until evidence_validator has confirmed or rejected this finding."
    )

    @model_validator(mode="after")
    def _at_most_one_target(self) -> "Finding":
        """A finding is about exactly one network asset OR one binary, never
        both — this was previously a no-op validator (bug: it took `v` and
        returned it unchanged, enforcing nothing). Every current producer
        (Web/Binary/Network-lead findings) already only ever sets one of
        the two; this makes that an enforced invariant instead of an
        accidental one."""
        if self.asset_id and self.binary_id:
            raise ValueError(
                f"finding {self.finding_id!r} sets both asset_id ({self.asset_id!r}) and "
                f"binary_id ({self.binary_id!r}); a finding must reference exactly one target"
            )
        return self


# ---------------------------------------------------------------------------
# Agent task / result (PRD Part 11 / Part 9)
# ---------------------------------------------------------------------------


class AgentTask(BaseModel):
    schema_version: str = SCHEMA_VERSION
    task_id: str
    assessment_id: str
    agent_id: AgentId
    task_type: str
    input_data: dict[str, Any] = Field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    output_data: dict[str, Any] | None = None
    error_message: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class AgentResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    agent_id: AgentId
    assessment_id: str
    execution_status: TaskStatus
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    discovered_endpoints: list[str] = Field(default_factory=list, description="Web Agent only.")
    tool_executions: list[dict[str, Any]] = Field(
        default_factory=list, description="Audit trail: {tool, args, exit_code, duration_s, ...}"
    )
    errors: list[str] = Field(default_factory=list)
    completion_time: datetime = Field(default_factory=_utcnow)
    duration_seconds: float | None = None


# ---------------------------------------------------------------------------
# External Network Vulnerability Agent integration contract (PRD Part 6)
# ---------------------------------------------------------------------------


class ExternalNetworkFinding(BaseModel):
    """What the teammate's Network Vulnerability Agent must POST to
    `/assessments/{assessment_id}/external-findings`. Kept intentionally close
    to `Finding` but decoupled so his component's evolution doesn't force
    changes here — `to_finding()` performs the translation.
    """

    schema_version: str = SCHEMA_VERSION
    assessment_id: str
    scope_id: str
    agent_id: Literal["network_vulnerability_agent"] = "network_vulnerability_agent"
    asset_id: str
    service_id: str | None = None
    finding_id: str
    title: str
    description: str = ""
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    status: FindingStatus = FindingStatus.SUSPECTED
    evidence_refs: list[str] = Field(default_factory=list)
    remediation: str | None = None
    execution_status: TaskStatus = TaskStatus.COMPLETED

    def to_finding(self) -> Finding:
        return Finding(
            finding_id=self.finding_id,
            assessment_id=self.assessment_id,
            agent_id=AgentId.NETWORK_VULNERABILITY,
            surface=Surface.NETWORK,
            asset_id=self.asset_id,
            service_id=self.service_id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            confidence=self.confidence,
            status=self.status,
            evidence_refs=self.evidence_refs,
            remediation=self.remediation,
            ptes_phase=PtesPhase.VULNERABILITY_ANALYSIS,
            detection_method="network_vulnerability_agent",
        )


# ---------------------------------------------------------------------------
# Network graph contract consumed by the adapter (PRD Part 5)
# ---------------------------------------------------------------------------


class NetworkGraphServiceRecord(BaseModel):
    """Normalised service record. Covers both the provisional static-file
    contract and the real Probe API contract (docs/CONTRACT.md); see
    app/adapters/network_graph_adapter.py for the two source-specific
    parsers that both produce this same shape."""

    service_id: str
    asset_id: str
    port: int
    protocol: str = "tcp"
    service_name: str | None = None
    version: str | None = None
    product: str | None = Field(default=None, description="From Probe's nmap-derived service.product, when available.")
    banner: str | None = Field(default=None, description="Raw banner text, when Probe captured one.")


class NetworkGraphAssetRecord(BaseModel):
    asset_id: str
    ip: str | None = None
    hostname: str | None = None
    asset_type: str = "host"
    services: list[NetworkGraphServiceRecord] = Field(default_factory=list)
    held: bool = Field(
        default=False,
        description="True when Probe found this asset inside a held (hidden, not-yet-approved) segment. "
        "Must never be offered as a web/binary assessment target regardless of AssessmentPolicy — "
        "see network_graph_adapter.extract_http_services and ScopeGuard.",
    )
    verdict: str | None = Field(
        default=None, description="Probe's reachability verdict (e.g. CONFIRMED_ONLINK), when sourced from Probe."
    )


class NetworkGraphEdgeRecord(BaseModel):
    source: str
    target: str
    relation: str = "CONNECTS_TO"


class NetworkGraph(BaseModel):
    """Normalised, in-memory representation produced by the Network Graph
    Adapter. This is NOT the wire format — `network_graph_adapter.py` accepts
    several tolerant wire shapes and always produces this."""

    schema_version: str = SCHEMA_VERSION
    scope_id: str
    generated_by: str = "network_probe"
    assets: list[NetworkGraphAssetRecord] = Field(default_factory=list)
    edges: list[NetworkGraphEdgeRecord] = Field(default_factory=list)
    raw_source_ref: str | None = None
