"""Item 9: live_assessment must refuse to start while synthetic fixtures are still enabled."""
from __future__ import annotations

import pytest

from app.core.config import settings
from app.core.execution_profile import ExecutionProfileError, preflight_check


@pytest.fixture(autouse=True)
def _restore_settings():
    original = (settings.execution_profile, settings.web_agent_use_fixtures, settings.binary_agent_use_fixtures)
    yield
    settings.execution_profile, settings.web_agent_use_fixtures, settings.binary_agent_use_fixtures = original


def test_synthetic_test_profile_always_passes(monkeypatch):
    monkeypatch.setattr(settings, "execution_profile", "synthetic_test")
    monkeypatch.setattr(settings, "web_agent_use_fixtures", True)
    monkeypatch.setattr(settings, "binary_agent_use_fixtures", True)
    preflight_check()  # does not raise


def test_live_assessment_refuses_to_start_with_web_fixtures_enabled(monkeypatch):
    monkeypatch.setattr(settings, "execution_profile", "live_assessment")
    monkeypatch.setattr(settings, "web_agent_use_fixtures", True)
    monkeypatch.setattr(settings, "binary_agent_use_fixtures", False)
    with pytest.raises(ExecutionProfileError, match="web_agent_use_fixtures"):
        preflight_check()


def test_live_assessment_refuses_to_start_with_binary_fixtures_enabled(monkeypatch):
    monkeypatch.setattr(settings, "execution_profile", "live_assessment")
    monkeypatch.setattr(settings, "web_agent_use_fixtures", False)
    monkeypatch.setattr(settings, "binary_agent_use_fixtures", True)
    with pytest.raises(ExecutionProfileError, match="binary_agent_use_fixtures"):
        preflight_check()


def test_live_assessment_passes_once_both_fixture_flags_are_off(monkeypatch):
    monkeypatch.setattr(settings, "execution_profile", "live_assessment")
    monkeypatch.setattr(settings, "web_agent_use_fixtures", False)
    monkeypatch.setattr(settings, "binary_agent_use_fixtures", False)
    preflight_check()


def test_unknown_profile_is_rejected(monkeypatch):
    monkeypatch.setattr(settings, "execution_profile", "production")
    with pytest.raises(ExecutionProfileError):
        preflight_check()
