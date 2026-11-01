import pytest

from app.adapters.network_graph_adapter import JSONFileNetworkGraphSource, load_network_graph
from app.core.exceptions import ScopeViolationError
from app.core.schemas import AssessmentPolicy
from app.core.scope_guard import ScopeGuard
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "network_graphs" / "sample_graph.json"


@pytest.fixture
def graph():
    return load_network_graph(JSONFileNetworkGraphSource(FIXTURE))


def test_asset_out_of_scope_denied(graph):
    policy = AssessmentPolicy(approved_asset_ids=["HOST-001"])
    guard = ScopeGuard(policy, graph)
    guard.check_asset_in_scope("HOST-001")  # ok
    with pytest.raises(ScopeViolationError):
        guard.check_asset_in_scope("HOST-002")


def test_service_assessment_requires_permission(graph):
    policy = AssessmentPolicy(allow_network_service_assessment=False)
    guard = ScopeGuard(policy, graph)
    with pytest.raises(ScopeViolationError):
        guard.check_service_assessment_allowed("HOST-001", "HOST-001:SVC-001")


def test_service_assessment_rejects_unknown_service(graph):
    policy = AssessmentPolicy(allow_network_service_assessment=True)
    guard = ScopeGuard(policy, graph)
    with pytest.raises(ScopeViolationError):
        guard.check_service_assessment_allowed("HOST-001", "HOST-001:SVC-999")


def test_web_crawl_requires_permission_and_approved_origin(graph):
    policy = AssessmentPolicy(
        allow_web_crawling=True,
        approved_web_origins=["https://web01.lab.local:443"],
        dry_run=False,
    )
    guard = ScopeGuard(policy, graph)
    guard.check_crawl_allowed("HOST-001", "https://web01.lab.local/search")
    with pytest.raises(ScopeViolationError):
        guard.check_crawl_allowed("HOST-001", "https://evil.example.com/")


def test_redirect_outside_approved_origin_denied(graph):
    policy = AssessmentPolicy(approved_web_origins=["https://web01.lab.local:443"], dry_run=False)
    guard = ScopeGuard(policy, graph)
    guard.check_redirect_allowed("https://web01.lab.local/", "https://web01.lab.local/login")
    with pytest.raises(ScopeViolationError):
        guard.check_redirect_allowed("https://web01.lab.local/", "https://attacker.example.com/")


def test_active_web_verification_disabled_by_default(graph):
    policy = AssessmentPolicy(approved_web_origins=["https://web01.lab.local:443"])
    guard = ScopeGuard(policy, graph)
    with pytest.raises(ScopeViolationError):
        guard.check_active_web_verification_allowed("HOST-001", "https://web01.lab.local/")


def test_binary_analysis_requires_permission(graph):
    guard = ScopeGuard(AssessmentPolicy(allow_binary_analysis=False), graph)
    with pytest.raises(ScopeViolationError):
        guard.check_binary_analysis_allowed("/inputs/binaries/sample.bin")
    guard2 = ScopeGuard(AssessmentPolicy(allow_binary_analysis=True, dry_run=False), graph)
    guard2.check_binary_analysis_allowed("/inputs/binaries/sample.bin")


def test_crawl_depth_enforced(graph):
    policy = AssessmentPolicy(max_crawl_depth=2)
    guard = ScopeGuard(policy, graph)
    guard.check_crawl_depth(2)
    with pytest.raises(ScopeViolationError):
        guard.check_crawl_depth(3)


def test_audit_log_records_denied_and_allowed(graph):
    policy = AssessmentPolicy(allow_binary_analysis=True, dry_run=False)
    guard = ScopeGuard(policy, graph)
    guard.check_binary_analysis_allowed("/inputs/binaries/sample.bin")
    assert len(guard.audit_log) == 1
    assert guard.audit_log[0].allowed is True


def test_dry_run_blocks_an_otherwise_authorised_call(graph):
    """Regression: AssessmentPolicy.dry_run (default True) was documented as
    preventing real tool execution but nothing ever checked it — every
    check_*_allowed() call just returned normally regardless, so a caller's
    real httpx/subprocess/API call always ran. Fixed in ScopeGuard._allow()."""
    policy = AssessmentPolicy(allow_binary_analysis=True, dry_run=True)
    guard = ScopeGuard(policy, graph)
    with pytest.raises(ScopeViolationError):
        guard.check_binary_analysis_allowed("/inputs/binaries/sample.bin")
    # Still recorded as "allowed" in the audit trail (the policy WOULD permit
    # it) — dry_run means "don't execute", not "deny".
    assert guard.audit_log[-1].allowed is True
    assert guard.audit_log[-1].dry_run is True


def test_empty_approved_web_origins_still_denies_third_party_domains(graph):
    """Regression: check_web_target_in_scope's `if self._approved_origins and origin not in
    self._approved_origins` only enforced the restriction when the set was non-empty -- an empty
    approved_web_origins (e.g. app.orchestrator.__main__'s own default policy, which never sets it) didn't
    mean "nothing is approved," it meant "the check is skipped entirely." A real orchestrator run against a
    real target proved this: the Web Security Agent/ZAP were allowed to touch third-party CDN domains
    Katana's own crawl happened to reference (cdn.jsdelivr.net, cdnjs.cloudflare.com), confirmed directly
    from that run's own scope_guard audit log, not merely inferred. Fixed by defaulting to the graph's own
    web-shaped services instead of to "everything" -- the same shape of fallback _approved_asset_ids
    already had."""
    policy = AssessmentPolicy(allow_passive_web_analysis=True, dry_run=False)  # approved_web_origins unset
    guard = ScopeGuard(policy, graph)
    with pytest.raises(ScopeViolationError):
        guard.check_web_target_in_scope("HOST-002", "https://cdn.jsdelivr.net/npm/bootstrap.min.css")
    with pytest.raises(ScopeViolationError):
        guard.check_web_target_in_scope("HOST-002", "https://cdnjs.cloudflare.com/")


def test_empty_approved_web_origins_defaults_to_the_graphs_own_web_services(graph):
    """The other half of the same fix: an empty approved_web_origins must still allow the graph's own,
    already-authorised web services -- HOST-001 is https:443, HOST-002 is http:80 in the fixture graph --
    not deny everything as an overcorrection."""
    policy = AssessmentPolicy(allow_passive_web_analysis=True, dry_run=False)
    guard = ScopeGuard(policy, graph)
    guard.check_web_target_in_scope("HOST-001", "https://web01.lab.local/")
    guard.check_web_target_in_scope("HOST-001", "https://192.168.60.10/")
    guard.check_web_target_in_scope("HOST-002", "http://api01.lab.local/")
    guard.check_web_target_in_scope("HOST-002", "http://192.168.60.11/")


def test_explicit_approved_web_origins_still_overrides_the_default(graph):
    """An explicit, non-empty approved_web_origins must still behave exactly as before this fix -- the
    default-from-graph fallback only applies when the policy leaves it empty."""
    policy = AssessmentPolicy(approved_web_origins=["https://web01.lab.local:443"], dry_run=False,
                              allow_passive_web_analysis=True)
    guard = ScopeGuard(policy, graph)
    guard.check_web_target_in_scope("HOST-001", "https://web01.lab.local/")
    with pytest.raises(ScopeViolationError):
        # HOST-002's own graph-known origin is no longer in the default set once an explicit,
        # narrower list is given -- that's the operator's deliberate choice, not a bug.
        guard.check_web_target_in_scope("HOST-002", "http://api01.lab.local/")
