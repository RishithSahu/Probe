"""Crawler subprocess boundaries tested without launching a crawler."""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from app.agents.web_security import crawler
from app.core.exceptions import ToolExecutionError
from app.core.schemas import AssessmentPolicy
from app.core.scope_guard import ScopeGuard


@pytest.mark.parametrize("seed, accepted, denied", [
    ("http://example.test/", ["http://example.test/x", "http://example.test:80/x"], ["http://example.test.evil/x", "https://example.test/", "http://example.test:81/", "http://example.test@evil.test/"]),
    ("https://example.test:8443/", ["https://example.test:8443/x"], ["https://example.test/", "https://example.test:443/", "https://example.test:84430/"]),
    ("http://[::1]:8080/", ["http://[::1]:8080/x"], ["http://[::1]:8081/", "http://[::1]/"]),
])
def test_scope_matches_only_the_authorised_origin(seed, accepted, denied):
    pattern = re.compile(crawler._origin_scope_regex(seed))
    assert all(pattern.match(url) for url in accepted)
    assert not any(pattern.match(url) for url in denied)


def test_port_zero_cannot_widen_a_crawl_to_the_default_port():
    with pytest.raises(ToolExecutionError, match="non-zero"):
        crawler._origin_scope_regex("http://example.test:0/")


def guard():
    return ScopeGuard(AssessmentPolicy(
        allow_web_crawling=True, dry_run=False, approved_asset_ids=["HOST"],
        approved_web_origins=["http://example.test"],
    ))


def test_crawl_passes_controls_before_work_and_filters_external_output(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(crawler, "_katana_available", lambda: True)

    def run(args, **kwargs):
        calls.append(args)
        if "-h" in args:
            return SimpleNamespace(returncode=0, stdout="-crawl-scope -disable-redirects", stderr="")
        return SimpleNamespace(returncode=0, stdout='{"endpoint":"http://example.test/ok"}\n{"endpoint":"http://evil.test/out"}', stderr="")

    monkeypatch.setattr(crawler.subprocess, "run", run)
    result = crawler.crawl("http://example.test/", asset_id="HOST", scope_guard=guard(), depth=1, rate_per_second=1, output_dir=tmp_path)
    assert "-h" in calls[0]
    # -dr/-disable-redirects is deliberately NOT passed: it disables following ANY
    # redirect (in-scope or not), not just out-of-scope ones, which silently
    # truncated every real crawl to one page -- see crawler.py's own comment.
    # -cs (crawl-scope regex) is the actual, sufficient bound on where redirects
    # (and every other discovered URL) may go; the Scope Guard re-checks on top.
    assert "-dr" not in calls[1] and "-cs" in calls[1]
    assert [ep.url for ep in result.endpoints] == ["http://example.test/ok"]


def test_unsupported_scope_controls_stop_before_crawling(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(crawler, "_katana_available", lambda: True)
    monkeypatch.setattr(crawler.subprocess, "run", lambda args, **kw: calls.append(args) or SimpleNamespace(returncode=0, stdout="old tool", stderr=""))
    with pytest.raises(ToolExecutionError, match="crawl not started"):
        crawler.crawl("http://example.test/", asset_id="HOST", scope_guard=guard(), depth=1, rate_per_second=1, output_dir=tmp_path)
    assert len(calls) == 1 and "-h" in calls[0]


def test_partial_tool_failure_is_not_returned_as_a_success(monkeypatch, tmp_path):
    monkeypatch.setattr(crawler, "_katana_available", lambda: True)
    monkeypatch.setattr(crawler, "_check_scope_capabilities", lambda: None)
    monkeypatch.setattr(crawler.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1, stdout='{"endpoint":"http://example.test/ok"}', stderr="failure"))
    with pytest.raises(ToolExecutionError, match="partial output retained"):
        crawler.crawl("http://example.test/", asset_id="HOST", scope_guard=guard(), depth=1, rate_per_second=1, output_dir=tmp_path)
    assert len(list(tmp_path.glob("katana_*.jsonl"))) == 1


def test_help_timeout_cannot_start_a_crawl(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(crawler, "_katana_available", lambda: True)

    def run(args, **kwargs):
        calls.append(args)
        raise crawler.subprocess.TimeoutExpired(args, 5)

    monkeypatch.setattr(crawler.subprocess, "run", run)
    with pytest.raises(ToolExecutionError, match="Could not verify"):
        crawler.crawl("http://example.test/", asset_id="HOST", scope_guard=guard(), depth=1, rate_per_second=1, output_dir=tmp_path)
    assert len(calls) == 1


def test_real_subprocess_call_survives_non_cp1252_output(monkeypatch, tmp_path):
    """Regression: found against a real live target, invisible with any fixture/synthetic test data.
    text=True without an explicit encoding uses the platform default codec (cp1252 on Windows), which
    raised UnicodeDecodeError the moment a real tool's real output contained an ordinary UTF-8 byte
    sequence a fixture would never contain. This calls the REAL subprocess.run inside
    _check_scope_capabilities (not a mock of it), against a real child process, to prove the actual
    encoding= kwarg is in effect -- a mocked subprocess.run can't exercise this at all."""
    import sys
    import textwrap

    fake_katana = tmp_path / "fake_katana.py"
    fake_katana.write_text(textwrap.dedent("""
        import sys
        sys.stdout.buffer.write("-crawl-scope -disable-redirects \\u20ac".encode("utf-8"))
    """))
    monkeypatch.setattr(crawler.settings, "katana_binary", sys.executable)
    original_run = crawler.subprocess.run

    def run_via_python(args, **kwargs):
        real_args = [sys.executable, str(fake_katana)] if args[1:] == ["-h"] else args
        return original_run(real_args, **kwargs)

    monkeypatch.setattr(crawler.subprocess, "run", run_via_python)
    crawler._check_scope_capabilities()  # must not raise UnicodeDecodeError
