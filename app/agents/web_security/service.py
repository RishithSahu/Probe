"""Optional standalone FastAPI service for the Web Security Agent.

Used when `app/main.py`'s Orchestrator is configured with
`APE_WEB_AGENT_SERVICE_URL` (see app/core/config.py and
app/orchestrator/nodes.py::dispatch_specialist_agents), matching the Docker
Compose `web-agent` service — a separate container so Katana can be
installed there without bloating the orchestrator image. Reconstructs a
`ScopeGuard` from the posted policy/graph rather than trusting the caller's
own authorisation decision, so this service enforces scope independently of
whoever calls it.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

from app.agents.web_security.agent import WebTarget, run_web_security_agent
from app.core.config import settings
from app.core.schemas import AgentResult, AssessmentPolicy, NetworkGraph
from app.core.scope_guard import ScopeGuard

app = FastAPI(title="Web Security Agent service")


class WebAgentRunRequest(BaseModel):
    assessment_id: str
    targets: list[tuple[str, str]]  # (asset_id, url)
    policy: AssessmentPolicy
    network_graph: NetworkGraph | None = None


@app.post("/run", response_model=AgentResult)
def run(request: WebAgentRunRequest) -> AgentResult:
    guard = ScopeGuard(request.policy, request.network_graph)
    targets = [WebTarget(asset_id=aid, url=url) for aid, url in request.targets]
    output_dir = Path(settings.evidence_dir) / request.assessment_id
    output_dir.mkdir(parents=True, exist_ok=True)
    return run_web_security_agent(
        targets, assessment_id=request.assessment_id, scope_guard=guard, policy=request.policy, output_dir=output_dir,
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "agent": "web_security_agent"}
