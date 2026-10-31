from pathlib import Path

from app.agents.web_security.agent import WebTarget, run_web_security_agent
from app.agents.web_security.crawler import crawl
from app.agents.web_security.fingerprint import fingerprint_url
from app.agents.web_security.zap_integration import run_passive_scan
from app.core.exceptions import ScopeViolationError
from app.core.schemas import AssessmentPolicy, TaskStatus
from app.core.scope_guard import ScopeGuard
import pytest


def _guard(base_url: str, **policy_kwargs) -> ScopeGuard:
    policy = AssessmentPolicy(
        allow_passive_web_analysis=True,
        allow_web_crawling=True,
        approved_web_origins=[base_url],
        approved_asset_ids=["HOST-001"],
        **policy_kwargs,
    )
    return ScopeGuard(policy)


def test_fingerprint_detects_missing_headers_and_insecure_cookie(synthetic_web_server):
    guard = _guard(synthetic_web_server)
    result = fingerprint_url(synthetic_web_server + "/", asset_id="HOST-001", scope_guard=guard)
    assert result.status_code == 200
    assert result.error is None
    assert result.cookies[0]["secure"] is False


def test_fingerprint_rejects_out_of_scope_url(synthetic_web_server):
    guard = _guard(synthetic_web_server)
    with pytest.raises(ScopeViolationError):
        fingerprint_url("http://not-approved.example.com/", asset_id="HOST-001", scope_guard=guard)


def test_fingerprint_follows_redirect_but_rejects_out_of_scope_target(synthetic_web_server):
    guard = _guard(synthetic_web_server)
    with pytest.raises(ScopeViolationError):
        fingerprint_url(synthetic_web_server + "/redirect-out-of-scope", asset_id="HOST-001", scope_guard=guard)


def test_crawl_without_katana_uses_fixture(tmp_path, synthetic_web_server):
    guard = _guard(synthetic_web_server)
    result = crawl(
        synthetic_web_server, asset_id="HOST-001", scope_guard=guard, depth=2, rate_per_second=2,
        output_dir=tmp_path,
    )
    assert result.used_fixture is True
    assert len(result.endpoints) > 0


def test_crawl_denied_without_permission(tmp_path, synthetic_web_server):
    policy = AssessmentPolicy(
        allow_web_crawling=False, approved_web_origins=[synthetic_web_server], approved_asset_ids=["HOST-001"],
    )
    guard = ScopeGuard(policy)
    with pytest.raises(ScopeViolationError):
        crawl(synthetic_web_server, asset_id="HOST-001", scope_guard=guard, depth=1, rate_per_second=1, output_dir=tmp_path)


def test_zap_passive_scan_uses_fixture_when_zap_unreachable(synthetic_web_server):
    guard = _guard(synthetic_web_server)
    result = run_passive_scan(synthetic_web_server + "/", asset_id="HOST-001", scope_guard=guard)
    assert result.used_fixture is True
    assert len(result.alerts) > 0


def test_full_web_agent_run_produces_findings(tmp_path, synthetic_web_server):
    guard = _guard(synthetic_web_server)
    policy = AssessmentPolicy(
        allow_passive_web_analysis=True,
        allow_web_crawling=True,
        approved_web_origins=[synthetic_web_server],
        approved_asset_ids=["HOST-001"],
    )
    targets = [WebTarget(asset_id="HOST-001", url=synthetic_web_server + "/")]
    result = run_web_security_agent(
        targets, assessment_id="ASSESSMENT-001", scope_guard=guard, policy=policy, output_dir=tmp_path,
    )
    assert result.execution_status == TaskStatus.COMPLETED
    assert len(result.findings) > 0
    assert all(f.status.value == "suspected" for f in result.findings)
    assert len(result.discovered_endpoints) > 0


def test_web_agent_active_scan_skipped_when_not_authorised(tmp_path, synthetic_web_server):
    guard = _guard(synthetic_web_server)
    policy = AssessmentPolicy(
        allow_passive_web_analysis=True,
        allow_web_crawling=False,
        allow_active_web_verification=False,
        approved_web_origins=[synthetic_web_server],
        approved_asset_ids=["HOST-001"],
    )
    targets = [WebTarget(asset_id="HOST-001", url=synthetic_web_server + "/")]
    result = run_web_security_agent(
        targets, assessment_id="ASSESSMENT-001", scope_guard=guard, policy=policy, output_dir=tmp_path,
    )
    assert not any("zap_active" in te.get("tool", "") for te in result.tool_executions)
