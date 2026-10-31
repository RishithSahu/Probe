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
