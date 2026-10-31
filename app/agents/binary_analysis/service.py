"""Optional standalone FastAPI service for the Binary Analysis Agent.

Mirrors `app/agents/web_security/service.py` — used when the Orchestrator is
configured with `APE_BINARY_AGENT_SERVICE_URL`, matching the Docker Compose
`binary-agent` service (a separate container so Ghidra + a JDK can be
installed there without bloating the orchestrator image).
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

from app.agents.binary_analysis.agent import run_binary_analysis_agent
from app.core.config import settings
from app.core.schemas import AgentResult, AssessmentPolicy, NetworkGraph
from app.core.scope_guard import ScopeGuard

app = FastAPI(title="Binary Analysis Agent service")


class BinaryAgentRunRequest(BaseModel):
    assessment_id: str
    binaries: list[tuple[str, str]]  # (binary_id, file_path)
    policy: AssessmentPolicy
    network_graph: NetworkGraph | None = None


@app.post("/run", response_model=AgentResult)
def run(request: BinaryAgentRunRequest) -> AgentResult:
    guard = ScopeGuard(request.policy, request.network_graph)
    binaries = [(bid, Path(p)) for bid, p in request.binaries]
    output_dir = Path(settings.evidence_dir) / request.assessment_id
    output_dir.mkdir(parents=True, exist_ok=True)
    return run_binary_analysis_agent(binaries, assessment_id=request.assessment_id, scope_guard=guard, output_dir=output_dir)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "agent": "binary_analysis_agent"}
