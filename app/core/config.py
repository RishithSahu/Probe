"""Application configuration.

All runtime-affecting settings are environment-driven (see `.env.example`) so the
same code can run against synthetic fixtures in development and against real
tool integrations once they are available in the assessment environment.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="APE_", extra="ignore")

    # --- Service identity -------------------------------------------------
    app_name: str = "autonomous-pentest-engine"
    environment: str = Field(default="development")  # development | hackathon | production

    # --- Database -----------------------------------------------------------
    # SQLite by default — zero external services to stand up for a hackathon
    # dev/demo environment. The file lives under evidence/ so it's covered by
    # the same persistent volume/bind-mount as everything else. Swap this for
    # another SQLAlchemy URL (e.g. PostgreSQL) if a shared/concurrent-write
    # deployment is needed later; app/database/session.py's only SQLite-
    # specific behaviour is the `check_same_thread` connect arg below.
    database_url: str = Field(
        default="sqlite:///evidence/ape.db",
        description="SQLAlchemy connection string. Defaults to a local SQLite file.",
    )

    # --- Storage --------------------------------------------------------------
    evidence_dir: Path = Field(default=Path("evidence"))
    inputs_dir: Path = Field(default=Path("inputs"))
    network_graph_dir: Path = Field(default=Path("inputs/network_graphs"))
    binaries_dir: Path = Field(default=Path("inputs/binaries"))
    reports_dir: Path = Field(default=Path("evidence/reports"))
    authorisations_path: Path | None = Field(
        default=None,
        description="Optional path to Probe's authorisations.json (explicit scope/method grants). When set, "
        "content discovery applies any matching method_grant's header to its own requests -- see "
        "app/adapters/authorisation_grants.py. Never required; absent means no extra headers are applied.",
    )

    # --- Web Security Agent tool integrations ---------------------------------
    katana_binary: str = Field(default="katana")
    # NOT 8080: that's probe_api_url's default below. A local, non-Docker dev run with both services
    # pointed at their own defaults would have every ZAP call silently hit Probe's API instead (a 404,
    # indistinguishable from "ZAP unreachable" other than by reading the response body), falling back to
    # the synthetic fixture on every single call -- found live, this is the fix. Docker Compose is
    # unaffected: it sets APE_ZAP_API_URL to http://zap:8080 explicitly, a different hostname.
    zap_api_url: str = Field(default="http://127.0.0.1:8090")
    zap_api_key: str = Field(default="")
    httpx_timeout_seconds: float = Field(default=10.0)
    # synthetic_test: documented fixtures may stand in for Katana/ZAP/Ghidra when unavailable (local dev,
    # deterministic unit tests). live_assessment: nothing here may substitute synthetic data -- a missing
    # tool must produce an honest incomplete result (see app.core.execution_profile.preflight_check,
    # which the CLI calls before a --new-assessment/--resume run and refuses to start if this profile is
    # live_assessment but either *_use_fixtures flag below is still enabled).
    execution_profile: str = Field(default="synthetic_test")
    web_agent_use_fixtures: bool = Field(
        default=True,
        description="When true, missing external tools (Katana/ZAP) fall back to "
        "documented synthetic fixtures instead of failing the task.",
    )

    # --- Binary Analysis Agent tool integrations -------------------------------
    ghidra_install_dir: str = Field(default="")
    ghidra_project_dir: Path = Field(default=Path("evidence/ghidra_projects"))
    binary_agent_use_fixtures: bool = Field(default=True)
    binary_analysis_timeout_seconds: float = Field(default=300.0)

    # --- Orchestrator -----------------------------------------------------------
    agent_task_timeout_seconds: float = Field(default=600.0)
    max_concurrent_agent_tasks: int = Field(default=4)

    # Per-surface concurrency limits for app.orchestrator.autonomous_loop.run_concurrent_iteration --
    # separate resource pools so one surface's own tool cost can't starve the others out of the shared
    # max_inflight budget (a slow Ghidra analysis must not consume all available Web/Network capacity).
    # The effective cap on a dispatch call is min(max_inflight, this surface's own limit, 1-per-target).
    max_concurrent_web_tasks: int = Field(default=3, description="Cap on simultaneously RUNNING Web Security tasks.")
    max_concurrent_network_tasks: int = Field(
        default=3, description="Cap on simultaneously RUNNING Network Vulnerability Detective tasks."
    )
    max_concurrent_binary_tasks: int = Field(
        default=2, description="Cap on simultaneously RUNNING Binary Analysis tasks (Ghidra is the heaviest tool here)."
    )

    # When set, the Orchestrator dispatches to these as remote FastAPI
    # services (see app/agents/*/service.py, Dockerfile.web, Dockerfile.binary)
    # over HTTP instead of calling the agent's Python module in-process. This
    # is how the "web-agent"/"binary-agent" Docker Compose services are
    # actually used; unset (the default for tests and single-process runs),
    # the Orchestrator imports and calls the agent code directly in the same
    # process, which is simpler for local development.
    web_agent_service_url: str | None = Field(default=None)
    binary_agent_service_url: str | None = Field(default=None)
    agent_service_timeout_seconds: float = Field(default=650.0)

    # Name of a ZAP scan policy (created in advance via the ZAP UI/API) that
    # excludes brute-force- and DoS-capable active rules. "Default Policy"
    # ships with ZAP itself; see README.md "OWASP ZAP active-scan policy" for
    # how to define a stricter one for a hackathon/lab engagement.
    zap_active_scan_policy_name: str = Field(default="Default Policy")

    # --- Network Discovery Probe integration (teammate's component, probe/) ----
    # Base URL of a running `python -m probe` instance (see docs/CONTRACT.md).
    # Probe normally runs directly on a host with raw-socket/admin access, not
    # in a container — when the orchestrator itself runs in Docker, this must
    # be reachable from inside the container: `http://host.docker.internal:8080`
    # on Docker Desktop (Windows/Mac), or the host's LAN/bridge IP on Linux.
    # Set to empty/None to disable the live integration entirely and fall back
    # to a static network-graph file supplied per-assessment.
    probe_api_url: str | None = Field(default="http://127.0.0.1:8080")
    probe_scan_max_age_seconds: float = Field(
        default=300.0, description="Passed to ProbeClient.ensure_scan(); see app/adapters/network_graph_adapter.py."
    )
    probe_ensure_scan_on_load: bool = Field(
        default=False,
        description="If true, load_network_graph asks Probe to (re)scan before reading the inventory, "
        "which can block for minutes on a cold scan. Default false: assumes Probe is already warmed up "
        "(e.g. run manually, or ensure_scan'd by another agent) so an assessment request never "
        "unexpectedly triggers new network traffic on its own.",
    )
    probe_auto_ingest_leads: bool = Field(
        default=True,
        description="When Probe is configured, automatically translate its leads() into network-surface "
        "Findings during ingest_network_agent_results, in addition to anything POSTed to "
        "/external-findings. See app/adapters/probe_leads.py.",
    )

    # --- Safety defaults (overridden per-assessment by AssessmentPolicy) ------
    default_active_web_verification_enabled: bool = Field(default=False)

    def ensure_directories(self) -> None:
        for path in (
            self.evidence_dir,
            self.network_graph_dir,
            self.binaries_dir,
            self.reports_dir,
            self.ghidra_project_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


settings = Settings()
