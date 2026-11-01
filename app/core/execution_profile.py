"""Fixture-free production mode (item 9).

Two execution profiles, set via `APE_EXECUTION_PROFILE`:
  synthetic_test   documented fixtures may stand in for Katana/ZAP/Ghidra when unavailable -- local dev,
                   deterministic unit tests. This is the default, so existing tests keep working unchanged.
  live_assessment  nothing may substitute synthetic data. A missing tool must produce an honest incomplete
                   result (analysis_depth=strings_only, used_fixture-tagged findings excluded from the
                   scheduler -- see app.orchestrator.scheduler and app.agents.web_security.findings), never
                   a fabricated one.

`preflight_check()` is the single gate: call it once before a real run starts (the CLI does, in
app.orchestrator.__main__.run). It raises, rather than silently downgrading the profile, if
`live_assessment` is selected but fixture fallbacks are still enabled -- a live run must not discover only
at finding-generation time that it was quietly fixture-backed the whole way.
"""
from __future__ import annotations

from app.core.config import settings
from app.core.exceptions import AppError

VALID_PROFILES = ("synthetic_test", "live_assessment")


class ExecutionProfileError(AppError):
    pass


def preflight_check() -> None:
    if settings.execution_profile not in VALID_PROFILES:
        raise ExecutionProfileError(
            f"APE_EXECUTION_PROFILE={settings.execution_profile!r} is not one of {VALID_PROFILES}"
        )
    if settings.execution_profile != "live_assessment":
        return
    enabled_fixture_flags = [
        name for name, enabled in (
            ("web_agent_use_fixtures", settings.web_agent_use_fixtures),
            ("binary_agent_use_fixtures", settings.binary_agent_use_fixtures),
        ) if enabled
    ]
    if enabled_fixture_flags:
        raise ExecutionProfileError(
            "execution_profile=live_assessment but synthetic fixtures are still enabled: "
            f"{', '.join(enabled_fixture_flags)}. A live assessment must never substitute synthetic data "
            "for a real tool's absence -- set these to false (an unavailable tool then produces an honest "
            "incomplete result instead) or switch back to execution_profile=synthetic_test."
        )
