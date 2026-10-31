"""Shared exception hierarchy.

Keeping these distinct (rather than raising bare `Exception`/`ValueError`
everywhere) lets the Orchestrator and FastAPI layer translate failures into the
correct task status (`failed` vs `skipped`) and HTTP response without guessing.
"""
from __future__ import annotations


class AppError(Exception):
    """Base class for all application-raised errors."""


class ScopeViolationError(AppError):
    """Raised by the Scope Guard when an operation targets something outside
    the authorised assessment scope. This must never be silently swallowed —
    callers should turn it into a `skipped`/`rejected` task outcome, not a crash
    that takes down the rest of the assessment."""


class DryRunSkipped(ScopeViolationError):
    """Raised by the Scope Guard instead of actually permitting a tool call
    when `AssessmentPolicy.dry_run` is set — the operation would have been
    authorised (recorded `allowed=True` in the audit log), but is not
    executed. Deliberately a `ScopeViolationError` subclass so every
    existing `except ScopeViolationError` call site already stops execution
    correctly without needing to know about dry-run specifically; callers
    that do want to tell the two apart can `except DryRunSkipped` first."""


class GraphValidationError(AppError):
    """Raised by the Network Graph Adapter when the supplied graph is malformed,
    missing required fields, or otherwise cannot be safely normalised."""


class EvidenceValidationError(AppError):
    """Raised when a finding references evidence that does not exist or does not
    satisfy the schema required for its claimed status."""


class ToolExecutionError(AppError):
    """Raised when an external tool (Katana, ZAP, Ghidra, file/readelf/checksec)
    fails, times out, or is unavailable and no fixture fallback is configured."""


class AssessmentNotFoundError(AppError):
    """Raised when an assessment_id does not exist in persistence."""


class AgentTaskError(AppError):
    """Raised for failures internal to a specialist agent's execution that should
    be recorded against that agent's AgentResult rather than propagated raw."""
