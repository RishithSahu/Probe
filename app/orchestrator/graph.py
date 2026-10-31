"""LangGraph workflow definition.

Wires the nodes in `app.orchestrator.nodes` into the graph described in PRD
Part 9.2. `dispatch_specialist_agents` (Web + Binary, run concurrently inside
via a thread pool — see dispatcher.py) and `ingest_network_agent_results`
(the external agent's already-submitted results) run as parallel branches
from `create_agent_tasks`, both converging on `aggregate_findings` — this is
the graph-level expression of "independent tasks execute concurrently" and
of "the Network Vulnerability Agent's results are ingested via an external
interface, not dispatched by this Orchestrator".
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from app.orchestrator import nodes
from app.orchestrator.state import OrchestratorState


def build_orchestrator_graph():
    graph = StateGraph(OrchestratorState)

    graph.add_node("validate_assessment", nodes.validate_assessment)
    graph.add_node("load_network_graph", nodes.load_network_graph)
    graph.add_node("normalise_network_graph", nodes.normalise_network_graph)
    graph.add_node("validate_scope", nodes.validate_scope)
    graph.add_node("create_agent_tasks", nodes.create_agent_tasks)
    graph.add_node("dispatch_specialist_agents", nodes.dispatch_specialist_agents)
    graph.add_node("handle_discovered_binaries", nodes.handle_discovered_binaries)
    graph.add_node("ingest_network_agent_results", nodes.ingest_network_agent_results)
    graph.add_node("aggregate_findings", nodes.aggregate_findings)
    graph.add_node("validate_evidence", nodes.validate_evidence)
    graph.add_node("build_attack_paths", nodes.build_attack_paths)
    graph.add_node("map_ptes_phases", nodes.map_ptes_phases)
    graph.add_node("generate_report", nodes.generate_report)
    graph.add_node("complete_assessment", nodes.complete_assessment)

    graph.add_edge(START, "validate_assessment")
    graph.add_edge("validate_assessment", "load_network_graph")
    graph.add_edge("load_network_graph", "normalise_network_graph")
    graph.add_edge("normalise_network_graph", "validate_scope")
    graph.add_edge("validate_scope", "create_agent_tasks")

    # Parallel branches: both are independent of each other and converge at
    # aggregate_findings. LangGraph runs fan-out branches from a shared
    # predecessor concurrently by default.
    graph.add_edge("create_agent_tasks", "dispatch_specialist_agents")
    graph.add_edge("create_agent_tasks", "ingest_network_agent_results")
    # handle_discovered_binaries is sequential after dispatch_specialist_agents (it reads web_agent_result
    # from state), but its branch still joins aggregate_findings in parallel with ingest_network_agent_results.
    graph.add_edge("dispatch_specialist_agents", "handle_discovered_binaries")
    graph.add_edge("handle_discovered_binaries", "aggregate_findings")
    graph.add_edge("ingest_network_agent_results", "aggregate_findings")

    graph.add_edge("aggregate_findings", "validate_evidence")
    graph.add_edge("validate_evidence", "build_attack_paths")
    graph.add_edge("build_attack_paths", "map_ptes_phases")
    graph.add_edge("map_ptes_phases", "generate_report")
    graph.add_edge("generate_report", "complete_assessment")
    graph.add_edge("complete_assessment", END)

    return graph.compile()


_compiled_graph = None


def get_orchestrator_graph():
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_orchestrator_graph()
    return _compiled_graph


def run_assessment(initial_state: OrchestratorState) -> OrchestratorState:
    """Synchronous convenience entry point used by the FastAPI background
    task and the synthetic end-to-end demo script."""
    compiled = get_orchestrator_graph()
    result = compiled.invoke(initial_state)
    return result
