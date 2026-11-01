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

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.core.exceptions import DryRunSkipped, ScopeViolationError
from app.core.schemas import AgentId, Confidence, Finding, NetworkGraph, NetworkGraphAssetRecord, NetworkGraphServiceRecord
from app.core.scope_guard import ScopeGuard

# Configurable, named weights -- the ONE place relative priority is tuned. Each factor is normalised to
# [0, 1] before weighting, so changing a weight here changes behaviour predictably, not by trial and error.
DEFAULT_WEIGHTS: dict[str, float] = {
    "objective_relevance": 3.0,   # connected to an existing, evidence-backed unresolved lead
    "evidence_strength": 2.0,     # how solid the evidence behind that lead is
    "weakness_depth": 2.0,        # a real protocol/binary/credential weakness, not cosmetic header hygiene
    "information_gain": 1.5,      # how much an unanswered question this could resolve
    "novelty": 1.5,               # not already attempted-without-result against the same evidence
    "execution_cost": 1.0,        # SUBTRACTED: cheaper investigations are preferred, all else equal
}

# The goal is finding and probing further into actual weaknesses -- a real protocol/credential/binary
# issue, never "which service leads to a flag." Cosmetic hygiene findings (a missing response header) are
# real, low-severity signal, not nothing -- but they must never outrank a genuine weakness just because
# they happen to exist. This is the one place that distinction is scored.
_LOW_WEAKNESS_DEPTH_METHODS = {"httpx_header_analysis", "httpx_cookie_analysis", "katana_endpoint_param_heuristic"}
_HIGH_WEAKNESS_DEPTH_METHODS = {
    "network_vulnerability:ftp_anonymous_login", "network_vulnerability:redis_auth_check",
    "network_vulnerability:postgresql_auth_check", "network_vulnerability:ssh_protocol_version",
    "hardcoded_credential", "recovered_credential", "unsafe_function_usage", "weak_binary_hardening",
    "suspicious_input_handling", "single_credential_verification", "zap_active_scan",
}


def _weakness_depth(backing_findings: list[Finding]) -> float:
    methods = {f.detection_method for f in backing_findings if f.detection_method}
    if methods & _HIGH_WEAKNESS_DEPTH_METHODS:
        return 1.0
    if methods and methods <= _LOW_WEAKNESS_DEPTH_METHODS:
        return 0.2
    return 0.5  # everything else (e.g. zap_passive_scan, unrecognised future methods) -- real signal, unclear depth

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
    # Plain DB fact -- a task row for this candidate already exists -- independent of novelty/scoring.
    # _reserve() uses THIS (not next_attempt_count) to decide whether a reservation may reclaim an
    # existing task_id. See the long comment in generate_candidates() for why conflating the two caused
    # an infinite no-progress loop.
    has_prior_attempt: bool = False
    # The set of finding_ids backing this candidate at the moment of this dispatch, persisted so the NEXT
    # generate_candidates() call can tell "genuinely new evidence" (a finding_id never seen before) apart
    # from "the same stable finding read again."
    finding_ids_at_dispatch: list[str] = field(default_factory=list)

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


def _probe_observation_strength(asset: NetworkGraphAssetRecord, service: NetworkGraphServiceRecord) -> float:
    """Rank *observed* services ahead of blind port-order enumeration.

    Probe may already have collected a bounded banner or HTTP inventory while
    discovering a port.  The old adapter discarded that context, leaving the
    scheduler to process hundreds of services lexicographically.  This is a
    generic information-gain signal: it never labels page text as a weakness,
    never derives a secret, and never changes scope.  It simply ensures a
    service for which the assessment already has meaningful, attributable
    observations reaches the appropriate specialist promptly.
    """
    score = 0.0
    if service.banner:
        score += 0.30
    observations = service.probe_observations
    if observations:
        score += 0.35
        # Structured HTTP inventories have one observation for every resource
        # actually seen.  Cap this so a large site cannot starve all other
        # surfaces indefinitely.
        for value in observations.values():
            if not isinstance(value, (str, dict)):
                continue
            try:
                parsed = json.loads(value) if isinstance(value, str) else value
            except (TypeError, ValueError):
                parsed = {}
            if isinstance(parsed, dict):
                resources = parsed.get("resources")
                if isinstance(resources, list):
                    score += min(len(resources), 8) * 0.04
    if "forwarder" in {role.lower() for role in asset.probe_roles}:
        score += 0.10
    return min(score, 1.0)


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
            observation_strength = _probe_observation_strength(asset, service)
            strongest = max((_confidence_value(f.confidence) for f in backing_findings), default=0.1)

            # BUG FIX (found live: a candidate spun 22,900+ reservation failures in a row without ever
            # being dispatched again or excluded). Root cause: novelty used to reset to "fresh"
            # (next_attempt_count=1) whenever the backing FINDING COUNT grew since the stored
            # finding_count_at_dispatch -- but a check that reproduces the SAME finding identically every
            # time (e.g. a stable, repeatable banner read) grows the count exactly once (0->1) and then
            # keeps that count forever; if the dispatch that produced it never got the chance to persist
            # the new count (see below), every later read sees "0 stored, 1 current" and treats it as
            # perpetually growing. Worse, `next_attempt_count` was ALSO the sole signal `_reserve` used to
            # decide whether a reservation may reclaim an EXISTING task_id (allow_reclaim = next_attempt_
            # count > 1) -- so "treated as fresh" and "there is no existing row to reclaim" were silently
            # conflated. Once a row already existed, "fresh" meant "the plain INSERT will fail and the
            # caller is told not to reclaim," so no dispatch ever happened again, no write ever updated the
            # stored evidence signature, and the candidate stayed permanently misjudged as freshly novel.
            #
            # Fixed with two independent changes:
            #   1. `has_prior_attempt` (used for allow_reclaim) is now a plain fact -- a task row for this
            #      candidate already exists, full stop -- never derived from the scorer's own novelty
            #      judgement. Eligibility-to-reclaim and scoring are now independent questions.
            #   2. Novelty's "is this genuinely new evidence" check compares the actual SET of backing
            #      finding_ids against the set seen at the last dispatch, not a bare count: a check that
            #      reproduces the identical finding every time contributes nothing to that set on repeat
            #      runs, so it correctly decays instead of reading as "grew" forever.
            current_finding_ids = {f.finding_id for f in backing_findings}
            seen_finding_ids: set[str] = set()
            for a in prior_attempts:
                seen_finding_ids.update(a.get("finding_ids_at_dispatch") or [])
            new_evidence = bool(current_finding_ids - seen_finding_ids)
            last_attempt_count = max((int(a.get("attempt_count", 1)) for a in prior_attempts), default=0)
            has_prior_attempt = bool(prior_attempts)
            if not has_prior_attempt or new_evidence:
                novelty = 1.0
                next_attempt_count = 1
            else:
                if last_attempt_count >= MAX_FRUITLESS_ATTEMPTS:
                    continue  # bounded retries exhausted with no new evidence -- not a candidate right now
                novelty = 0.05 / last_attempt_count
                next_attempt_count = last_attempt_count + 1

            candidates.append(Candidate(
                candidate_id=f"CANDIDATE-service-{service.service_id}",
                source=("finding_followup" if has_evidence else
                        ("probe_observed_service" if observation_strength else "unvisited_service")),
                asset_id=asset.asset_id, service_id=service.service_id, agent_id=agent_id,
                evidence_refs=[ref for f in backing_findings for ref in f.evidence_refs],
                factors={
                    "objective_relevance": 1.0 if has_evidence else observation_strength,
                    "evidence_strength": strongest if has_evidence else max(0.1, observation_strength),
                    "weakness_depth": _weakness_depth(backing_findings) if has_evidence else 0.3,
                    "information_gain": max(_information_gain(service.service_name, has_evidence), observation_strength),
                    "novelty": novelty,
                    "execution_cost": _execution_cost(agent_id),
                },
                note=(
                    f"backed by {len(backing_findings)} existing finding(s)" if has_evidence else
                    "Probe collected service-scoped observations; prioritised for specialist assessment"
                    if observation_strength else
                    "previously attempted with no useful result" if prior_attempts else
                    "unvisited service, no prior evidence"
                ),
                backing_findings_count=len(backing_findings),
                next_attempt_count=next_attempt_count,
                has_prior_attempt=has_prior_attempt,
                finding_ids_at_dispatch=sorted(current_finding_ids),
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
