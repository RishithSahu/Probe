"""Deterministic, evidence-based task scheduler.

Replaces "pick the first unvisited service" with a transparent, weighted score over every eligible
investigation opportunity -- new services, services an existing Finding already points at, and (recorded
for completeness, never auto-selected) binary-analysis follow-ups already created by the web-to-binary
handoff. Nothing here is specific to any one challenge, host, port, or service name: every signal comes from
the assessment's own `NetworkGraph`, `AgentTask` history, and `Finding` records.

Hard eligibility (ScopeGuard, policy flags, dependency state) is checked BEFORE scoring and can never be
overridden by a score -- see `_eligible`. The score, its individual factors, and a human-readable
explanation are returned alongside the winning candidate so the caller can persist them (never an
unexplained number from an LLM).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.exceptions import DryRunSkipped, ScopeViolationError
from app.core.schemas import AgentId, Confidence, Finding, NetworkGraph
from app.core.scope_guard import ScopeGuard

# Configurable, named weights -- the ONE place relative priority is tuned. Each factor is normalised to
# [0, 1] before weighting, so changing a weight here changes behaviour predictably, not by trial and error.
DEFAULT_WEIGHTS: dict[str, float] = {
    "objective_relevance": 3.0,   # connected to an existing, evidence-backed unresolved lead
    "evidence_strength": 2.0,     # how solid the evidence behind that lead is
    "information_gain": 1.5,      # how much an unanswered question this could resolve
    "novelty": 1.5,               # not already attempted-without-result against the same evidence
    "execution_cost": 1.0,        # SUBTRACTED: cheaper investigations are preferred, all else equal
}

# Bounded retries (item 7): a candidate that has been attempted this many times with NO growth in its
# backing evidence is removed from the queue entirely -- not scored low, excluded -- so the loop cannot
# spin forever re-running a check that has already told it everything it is going to. It returns the
# moment genuinely new evidence (a grown finding count) appears; this is not a permanent blacklist.
MAX_FRUITLESS_ATTEMPTS = 3


def _is_http(service_name: str | None) -> bool:
    return (service_name or "").lower() in {"http", "https", "http-alt", "https-alt", "http-proxy"}


def _confidence_value(confidence: Confidence | str | None) -> float:
    return {"high": 1.0, "medium": 0.6, "low": 0.3}.get(
        confidence.value if isinstance(confidence, Confidence) else str(confidence or "").lower(), 0.1
    )


@dataclass
class Candidate:
    candidate_id: str
    source: str  # "unvisited_service" | "finding_followup"
    asset_id: str
    service_id: str
    agent_id: AgentId
    evidence_refs: list[str] = field(default_factory=list)
    factors: dict[str, float] = field(default_factory=dict)
    note: str = ""
    backing_findings_count: int = 0
    next_attempt_count: int = 1

    def score(self, weights: dict[str, float] | None = None) -> float:
        weights = weights or DEFAULT_WEIGHTS
        total = 0.0
        for name, weight in weights.items():
            value = self.factors.get(name, 0.0)
            total += -weight * value if name == "execution_cost" else weight * value
        return total

    def explanation(self, weights: dict[str, float] | None = None) -> dict:
        weights = weights or DEFAULT_WEIGHTS
        contributions = {
            name: (-weights[name] * self.factors.get(name, 0.0) if name == "execution_cost"
                   else weights[name] * self.factors.get(name, 0.0))
            for name in weights
        }
        return {
            "candidate_id": self.candidate_id, "source": self.source, "note": self.note,
            "factors": dict(self.factors), "weighted_contributions": contributions,
            "total_score": sum(contributions.values()),
        }


def _execution_cost(agent_id: AgentId) -> float:
    return {AgentId.NETWORK_VULNERABILITY_DETECTIVE: 0.2, AgentId.WEB_SECURITY: 0.4,
            AgentId.BINARY_ANALYSIS: 0.6}.get(agent_id, 0.5)


def _information_gain(service_name: str | None, has_evidence: bool) -> float:
    if has_evidence:
        return 0.9
    if not service_name or service_name in ("unknown", "unknown?"):
        return 0.7  # an unidentified protocol is the least-understood thing in the graph
    if _is_http(service_name):
        return 0.4
    return 0.3


def _web_url_for(asset_id: str, service_id: str) -> str:
    """The same URL app.orchestrator.autonomous_loop._execute_objective actually dispatches to for this
    service -- port included. BUG FIX: this eligibility check used to always probe `http://{asset_id}/`
    (implicitly port 80) regardless of the service's real port, so a port-443/8080/etc. service's
    eligibility was checked against the WRONG origin. Invisible as long as ScopeGuard's empty-origin-list
    check was a no-op (see that fix's own note); once it actually enforces origins, checking the wrong URL
    here made an otherwise-legitimate candidate wrongly ineligible."""
    port = service_id.split(":")[1].split("/")[0]
    scheme = "https" if port in ("443", "8443") else "http"
    return f"{scheme}://{asset_id}:{port}/"


def _eligible(agent_id: AgentId, asset_id: str, service_id: str, *, guard: ScopeGuard) -> tuple[bool, str]:
    """The ONE gate a score can never override. Returns (eligible, reason-if-not)."""
    try:
        guard.check_asset_in_scope(asset_id)
        if agent_id == AgentId.WEB_SECURITY:
            guard.check_passive_web_analysis_allowed(asset_id, _web_url_for(asset_id, service_id))
        else:
            guard.check_service_assessment_allowed(asset_id, service_id)
    except DryRunSkipped:
        pass  # authorised in principle; execution itself will no-op under dry_run, which is correct
    except ScopeViolationError as exc:
        return False, str(exc)
    return True, ""


def generate_candidates(
    graph: NetworkGraph, existing_task_inputs: list[dict], findings: list[Finding], *, guard: ScopeGuard,
) -> list[Candidate]:
    """Every eligible investigation opportunity visible in the assessment's own evidence right now."""
    tasks_by_service: dict[str, list[dict]] = {}
    for t in existing_task_inputs:
        sid = str(t.get("service_id") or "")
        if sid:
            tasks_by_service.setdefault(sid, []).append(t)

    findings_by_service: dict[str, list[Finding]] = {}
    for f in findings:
        # A synthetic-fixture finding (ZAP/Katana unreachable -- see findings_from_zap_alerts/
        # findings_from_discovered_endpoints) must never make the scheduler treat a service as
        # evidence-backed; it is a documented stand-in, not real signal about that service.
        if f.service_id and not (f.detection_method or "").endswith("_synthetic_fixture"):
            findings_by_service.setdefault(f.service_id, []).append(f)

    candidates: list[Candidate] = []
    for asset in graph.assets:
        if asset.held:
            continue
        for service in asset.services:
            prior_attempts = tasks_by_service.get(service.service_id, [])
            backing_findings = findings_by_service.get(service.service_id, [])
            agent_id = AgentId.WEB_SECURITY if _is_http(service.service_name) else AgentId.NETWORK_VULNERABILITY_DETECTIVE

            eligible, reason = _eligible(agent_id, asset.asset_id, service.service_id, guard=guard)
            if not eligible:
                continue

            has_evidence = bool(backing_findings)
            strongest = max((_confidence_value(f.confidence) for f in backing_findings), default=0.1)
            # Novelty: full score if never attempted, or if backing evidence has GROWN since the last
            # attempt (item 6: new evidence always restores eligibility). Otherwise it decays further with
            # every repeat (1/attempt_count), and past MAX_FRUITLESS_ATTEMPTS the candidate is dropped
            # entirely -- a bounded retry limit, never a permanent one (see MAX_FRUITLESS_ATTEMPTS).
            last_attempt_count = max((int(a.get("attempt_count", 1)) for a in prior_attempts), default=0)
            finding_count_at_prior_best = max(
                (int(a.get("finding_count_at_dispatch", 0)) for a in prior_attempts), default=0
            )
            grew = len(backing_findings) > finding_count_at_prior_best
            if not prior_attempts or grew:
                novelty = 1.0
                next_attempt_count = 1
            else:
                if last_attempt_count >= MAX_FRUITLESS_ATTEMPTS:
                    continue  # bounded retries exhausted with no new evidence -- not a candidate right now
                novelty = 0.05 / last_attempt_count
                next_attempt_count = last_attempt_count + 1

            candidates.append(Candidate(
                candidate_id=f"CANDIDATE-service-{service.service_id}",
                source="finding_followup" if has_evidence else "unvisited_service",
                asset_id=asset.asset_id, service_id=service.service_id, agent_id=agent_id,
                evidence_refs=[ref for f in backing_findings for ref in f.evidence_refs],
                factors={
                    "objective_relevance": 1.0 if has_evidence else 0.0,
                    "evidence_strength": strongest if has_evidence else 0.1,
                    "information_gain": _information_gain(service.service_name, has_evidence),
                    "novelty": novelty,
                    "execution_cost": _execution_cost(agent_id),
                },
                note=(f"backed by {len(backing_findings)} existing finding(s)" if has_evidence
                     else ("previously attempted with no useful result" if prior_attempts
                           else "unvisited service, no prior evidence")),
                backing_findings_count=len(backing_findings),
                next_attempt_count=next_attempt_count,
            ))
    return candidates


def rank_candidates(candidates: list[Candidate], weights: dict[str, float] | None = None) -> list[Candidate]:
    """Highest score first, deterministic tie-break on candidate_id so re-running against unchanged
    evidence always orders the same way -- the one place both `select_next` (one winner) and a concurrent
    dispatcher (the top `max_inflight` winners) get their ordering from, so they can never disagree about
    which candidate is "next" after the first."""
    weights = weights or DEFAULT_WEIGHTS
    return sorted(candidates, key=lambda c: (-c.score(weights), c.candidate_id))


def select_next(candidates: list[Candidate], weights: dict[str, float] | None = None) -> tuple[Candidate | None, dict]:
    """Highest-scoring eligible candidate, with a persisted explanation. Deterministic tie-break on
    candidate_id so re-running against unchanged evidence always picks the same task."""
    weights = weights or DEFAULT_WEIGHTS
    if not candidates:
        return None, {"reason": "no eligible candidate: nothing in the current evidence/graph qualifies "
                               "for investigation under the active policy and scope"}
    ranked = rank_candidates(candidates, weights)
    winner = ranked[0]
    return winner, {
        "selected": winner.explanation(weights),
        "considered": [c.explanation(weights) for c in ranked],
    }
