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

    # --- Web Security Agent tool integrations ---------------------------------
    katana_binary: str = Field(default="katana")
    zap_api_url: str = Field(default="http://127.0.0.1:8080")
    zap_api_key: str = Field(default="")
    httpx_timeout_seconds: float = Field(default=10.0)
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
